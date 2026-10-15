"""Intra-method Dalvik register data-flow tracer for GATT service registrations."""

import re
from typing import Any, Dict, List, Optional, Set, Tuple

try:
    from androguard.core.dex import Operand
except ImportError:
    class Operand:
        REGISTER = 0
        KIND = 256

from ucsd.ble.normalizer import normalize_uuid
from ucsd.errors import InvalidUUIDError
from ucsd.registration.models import (
    AddServiceCallSite,
    EvidenceLevel,
    RegistrationFinding,
    ServiceConstructionSite,
    TraceStep,
    UnresolvedReason,
)


def is_register_operand(op: Any) -> bool:
    """Check if an operand represents a Dalvik register."""
    if isinstance(op, tuple) and len(op) >= 2:
        tag = op[0]
        if tag == Operand.REGISTER or tag == 0 or getattr(tag, "name", None) == "REGISTER":
            return isinstance(op[1], int)
    return False


def get_instruction_registers(ins: Any) -> List[int]:
    """Extract list of register indices referenced by instruction operands."""
    regs: List[int] = []
    operands = getattr(ins, "get_operands", lambda: [])()
    for op in operands:
        if is_register_operand(op):
            regs.append(op[1])
    return regs


def get_invoked_method_signature(ins: Any) -> Optional[str]:
    """Extract method signature descriptor string from an invoke instruction."""
    operands = getattr(ins, "get_operands", lambda: [])()
    for op in operands:
        if isinstance(op, tuple) and len(op) == 3 and isinstance(op[2], str):
            return op[2]
    # Fallback to get_output() parsing if operands format varies
    output = getattr(ins, "get_output", lambda: "")()
    if "->" in output:
        parts = output.split("->", 1)
        # Find start of class descriptor 'L...->...'
        m = re.search(r"L[^;\s]+;->[^\s]+", output)
        if m:
            return m.group(0)
    return None


class TrackedValue:
    """Base class for abstract register values."""
    pass


class StringLiteral(TrackedValue):
    """Register holds a known string constant."""
    def __init__(self, val: str, offset: int, reg: int):
        self.val = val
        self.offset = offset
        self.reg = reg

    def clone_for_reg(self, new_reg: int) -> "StringLiteral":
        return StringLiteral(self.val, self.offset, new_reg)


class UUIDObject(TrackedValue):
    """Register holds a java.util.UUID instance."""
    def __init__(
        self,
        source_uuid: Optional[str],
        offset: int,
        reg: int,
        trace_steps: List[TraceStep],
    ):
        self.source_uuid = source_uuid
        self.offset = offset
        self.reg = reg
        self.trace_steps = list(trace_steps)

    def clone_for_reg(self, new_reg: int) -> "UUIDObject":
        return UUIDObject(self.source_uuid, self.offset, new_reg, self.trace_steps)


class GattServiceObject(TrackedValue):
    """Register holds a BluetoothGattService instance."""
    def __init__(
        self,
        uuid_val: Optional[UUIDObject],
        resolved_uuid: Optional[str],
        service_type: Optional[int],
        offset: int,
        reg: int,
        trace_steps: List[TraceStep],
    ):
        self.uuid_val = uuid_val
        self.resolved_uuid = resolved_uuid
        self.service_type = service_type
        self.offset = offset
        self.reg = reg
        self.trace_steps = list(trace_steps)

    def clone_for_reg(self, new_reg: int) -> "GattServiceObject":
        return GattServiceObject(
            self.uuid_val,
            self.resolved_uuid,
            self.service_type,
            self.offset,
            new_reg,
            self.trace_steps,
        )


class UnresolvedObject(TrackedValue):
    """Register holds an untracked or clobbered object."""
    def __init__(self, description: str, offset: int, reg: int):
        self.description = description
        self.offset = offset
        self.reg = reg

    def clone_for_reg(self, new_reg: int) -> "UnresolvedObject":
        return UnresolvedObject(self.description, self.offset, new_reg)


# Opcodes that define/write to regs[0] and clobber any prior value
_CLOBBERING_OPCODES = {
    "const", "const/4", "const/16", "const-high16",
    "const-wide", "const-wide/16", "const-wide/32", "const-wide/high16",
    "new-instance", "new-array",
    "aget", "aget-wide", "aget-object", "aget-boolean", "aget-byte", "aget-char", "aget-short",
    "iget", "iget-wide", "iget-object", "iget-boolean", "iget-byte", "iget-char", "iget-short",
    "sget", "sget-wide", "sget-object", "sget-boolean", "sget-byte", "sget-char", "sget-short",
    "add-int", "sub-int", "mul-int", "div-int", "rem-int", "and-int", "or-int", "xor-int",
    "shl-int", "shr-int", "ushr-int",
    "add-int/2addr", "sub-int/2addr", "mul-int/2addr", "div-int/2addr",
    "instance-of", "check-cast",
}


def trace_method_registrations(
    dex_file: str,
    class_name: str,
    method_name: str,
    descriptor: str,
    instructions: List[Any],
) -> Tuple[List[RegistrationFinding], List[ServiceConstructionSite], List[AddServiceCallSite]]:
    """Simulate register state across a method's Dalvik bytecode instructions.

    Identifies:
    1. BluetoothGattService constructor call sites.
    2. BluetoothGattServer.addService call sites.
    3. Verified intra-method data-flow from UUID string literal to addService.

    Args:
        dex_file: Originating DEX file name.
        class_name: Declaring class name.
        method_name: Method name.
        descriptor: Method descriptor signature.
        instructions: Ordered list of Dalvik instruction objects.

    Returns:
        Tuple of (findings, construction_call_sites, add_service_call_sites).
    """
    findings: List[RegistrationFinding] = []
    construction_sites: List[ServiceConstructionSite] = []
    add_service_sites: List[AddServiceCallSite] = []

    # Map construction site object to its GattServiceObject representation
    constructions_tracked: List[Tuple[ServiceConstructionSite, GattServiceObject]] = []
    add_services_tracked: List[Tuple[AddServiceCallSite, Optional[TrackedValue], int, str, str]] = []

    reg_state: Dict[int, TrackedValue] = {}
    last_invoke: Optional[Tuple[str, List[int], int]] = None
    ins_offset = 0

    for ins in instructions:
        op_name = getattr(ins, "get_name", lambda: "")()
        op_len = getattr(ins, "get_length", lambda: 2)()
        current_off = ins_offset
        ins_offset += op_len

        regs = get_instruction_registers(ins)

        # 1. const-string / const-string/jumbo
        if op_name in ("const-string", "const-string/jumbo") and regs:
            dst_reg = regs[0]
            str_val = getattr(ins, "get_string", lambda: None)()
            if str_val is None:
                # Try getting from operands
                for op in getattr(ins, "get_operands", lambda: [])():
                    if isinstance(op, tuple) and len(op) == 3 and isinstance(op[2], str):
                        str_val = op[2]
                        break
            if str_val is not None:
                reg_state[dst_reg] = StringLiteral(str_val, current_off, dst_reg)
            else:
                reg_state[dst_reg] = UnresolvedObject("unresolved_string", current_off, dst_reg)

        # 2. move-object / move-object/from16 / move-object/16
        elif op_name in ("move-object", "move-object/from16", "move-object/16") and len(regs) >= 2:
            dst_reg, src_reg = regs[0], regs[1]
            if src_reg in reg_state:
                reg_state[dst_reg] = reg_state[src_reg].clone_for_reg(dst_reg)
            else:
                reg_state[dst_reg] = UnresolvedObject("copied_untracked_object", current_off, dst_reg)

        # 3. move-result-object
        elif op_name == "move-result-object" and regs:
            dst_reg = regs[0]
            if last_invoke is not None:
                inv_sig, inv_regs, inv_offset = last_invoke

                # Pattern A: UUID.fromString(String)
                if "Ljava/util/UUID;->fromString(Ljava/lang/String;)Ljava/util/UUID;" in inv_sig:
                    arg_reg = inv_regs[0] if inv_regs else None
                    arg_val = reg_state.get(arg_reg)
                    if isinstance(arg_val, StringLiteral):
                        trace = [
                            TraceStep(
                                step_index=0,
                                step_type="load_uuid_string",
                                instruction_offset=arg_val.offset,
                                opcode="const-string",
                                details={"register": arg_reg, "string_value": arg_val.val},
                            ),
                            TraceStep(
                                step_index=1,
                                step_type="uuid_from_string",
                                instruction_offset=inv_offset,
                                opcode="invoke-static",
                                details={"method": inv_sig, "input_register": arg_reg, "result_register": dst_reg},
                            ),
                        ]
                        reg_state[dst_reg] = UUIDObject(
                            source_uuid=arg_val.val,
                            offset=current_off,
                            reg=dst_reg,
                            trace_steps=trace,
                        )
                    else:
                        trace = [
                            TraceStep(
                                step_index=0,
                                step_type="uuid_from_string_unresolved_arg",
                                instruction_offset=inv_offset,
                                opcode="invoke-static",
                                details={"method": inv_sig, "input_register": arg_reg, "result_register": dst_reg},
                            )
                        ]
                        reg_state[dst_reg] = UUIDObject(
                            source_uuid=None,
                            offset=current_off,
                            reg=dst_reg,
                            trace_steps=trace,
                        )

                # Pattern B: ParcelUuid.getUuid()
                elif "Landroid/os/ParcelUuid;->getUuid()Ljava/util/UUID;" in inv_sig:
                    arg_reg = inv_regs[0] if inv_regs else None
                    p_val = reg_state.get(arg_reg)
                    if isinstance(p_val, UUIDObject) and p_val.source_uuid:
                        step = TraceStep(
                            step_index=len(p_val.trace_steps),
                            step_type="parcel_uuid_get_uuid",
                            instruction_offset=inv_offset,
                            opcode="invoke-virtual",
                            details={"method": inv_sig, "input_register": arg_reg, "result_register": dst_reg},
                        )
                        reg_state[dst_reg] = UUIDObject(
                            source_uuid=p_val.source_uuid,
                            offset=current_off,
                            reg=dst_reg,
                            trace_steps=p_val.trace_steps + [step],
                        )
                    else:
                        reg_state[dst_reg] = UUIDObject(source_uuid=None, offset=current_off, reg=dst_reg, trace_steps=[])

                # Pattern C: ParcelUuid.fromString(String)
                elif "Landroid/os/ParcelUuid;->fromString(Ljava/lang/String;)Landroid/os/ParcelUuid;" in inv_sig:
                    arg_reg = inv_regs[0] if inv_regs else None
                    arg_val = reg_state.get(arg_reg)
                    if isinstance(arg_val, StringLiteral):
                        trace = [
                            TraceStep(
                                step_index=0,
                                step_type="load_uuid_string",
                                instruction_offset=arg_val.offset,
                                opcode="const-string",
                                details={"register": arg_reg, "string_value": arg_val.val},
                            ),
                            TraceStep(
                                step_index=1,
                                step_type="parcel_uuid_from_string",
                                instruction_offset=inv_offset,
                                opcode="invoke-static",
                                details={"method": inv_sig, "input_register": arg_reg, "result_register": dst_reg},
                            ),
                        ]
                        reg_state[dst_reg] = UUIDObject(
                            source_uuid=arg_val.val,
                            offset=current_off,
                            reg=dst_reg,
                            trace_steps=trace,
                        )
                    else:
                        reg_state[dst_reg] = UUIDObject(source_uuid=None, offset=current_off, reg=dst_reg, trace_steps=[])
                else:
                    reg_state[dst_reg] = UnresolvedObject(f"return_from_{inv_sig}", current_off, dst_reg)
            else:
                reg_state[dst_reg] = UnresolvedObject("move_result_unknown", current_off, dst_reg)

        # 4. invoke-* instructions
        elif op_name.startswith("invoke-"):
            inv_sig = get_invoked_method_signature(ins) or ""
            last_invoke = (inv_sig, regs, current_off)

            # Check for BluetoothGattService constructor: <init>(Ljava/util/UUID;I)V
            if "Landroid/bluetooth/BluetoothGattService;-><init>" in inv_sig:
                service_reg = regs[0] if len(regs) > 0 else -1
                uuid_reg = regs[1] if len(regs) > 1 else -1
                type_reg = regs[2] if len(regs) > 2 else None

                uuid_val = reg_state.get(uuid_reg)
                if isinstance(uuid_val, UUIDObject) and uuid_val.source_uuid:
                    try:
                        norm_uuid = normalize_uuid(uuid_val.source_uuid)
                    except InvalidUUIDError:
                        norm_uuid = uuid_val.source_uuid

                    step = TraceStep(
                        step_index=len(uuid_val.trace_steps),
                        step_type="service_constructor",
                        instruction_offset=current_off,
                        opcode=op_name,
                        details={
                            "method": inv_sig,
                            "service_register": service_reg,
                            "uuid_register": uuid_reg,
                            "resolved_uuid": norm_uuid,
                        },
                    )
                    all_steps = uuid_val.trace_steps + [step]
                    srv_obj = GattServiceObject(
                        uuid_val=uuid_val,
                        resolved_uuid=norm_uuid,
                        service_type=None,
                        offset=current_off,
                        reg=service_reg,
                        trace_steps=all_steps,
                    )
                    if service_reg >= 0:
                        reg_state[service_reg] = srv_obj

                    site = ServiceConstructionSite(
                        dex_file=dex_file,
                        class_name=class_name,
                        method_name=method_name,
                        descriptor=descriptor,
                        instruction_offset=current_off,
                        service_register=service_reg,
                        uuid_register=uuid_reg,
                        service_type_register=type_reg,
                        resolved_uuid=norm_uuid,
                        unresolved_reason=None,
                    )
                    construction_sites.append(site)
                    constructions_tracked.append((site, srv_obj))
                else:
                    # Constructor called, but UUID register not traced to known literal
                    step = TraceStep(
                        step_index=0,
                        step_type="service_constructor_unresolved_uuid",
                        instruction_offset=current_off,
                        opcode=op_name,
                        details={
                            "method": inv_sig,
                            "service_register": service_reg,
                            "uuid_register": uuid_reg,
                        },
                    )
                    srv_obj = GattServiceObject(
                        uuid_val=None,
                        resolved_uuid=None,
                        service_type=None,
                        offset=current_off,
                        reg=service_reg,
                        trace_steps=[step],
                    )
                    if service_reg >= 0:
                        reg_state[service_reg] = srv_obj

                    site = ServiceConstructionSite(
                        dex_file=dex_file,
                        class_name=class_name,
                        method_name=method_name,
                        descriptor=descriptor,
                        instruction_offset=current_off,
                        service_register=service_reg,
                        uuid_register=uuid_reg,
                        service_type_register=type_reg,
                        resolved_uuid=None,
                        unresolved_reason=(
                            UnresolvedReason.CROSS_METHOD_UUID
                            if uuid_reg not in reg_state
                            else UnresolvedReason.DYNAMIC_UUID_EXPRESSION
                        ),
                    )
                    construction_sites.append(site)
                    constructions_tracked.append((site, srv_obj))

            # Check for BluetoothGattServer.addService(BluetoothGattService)
            elif "Landroid/bluetooth/BluetoothGattServer;->addService(Landroid/bluetooth/BluetoothGattService;)Z" in inv_sig:
                server_reg = regs[0] if len(regs) > 0 else -1
                service_reg = regs[1] if len(regs) > 1 else -1

                srv_val = reg_state.get(service_reg)
                is_resolved_locally = isinstance(srv_val, GattServiceObject)

                unresolved_reason = None
                if not is_resolved_locally:
                    if service_reg not in reg_state:
                        unresolved_reason = UnresolvedReason.CROSS_METHOD_SERVICE_OBJECT
                    elif (
                        isinstance(reg_state[service_reg], UnresolvedObject)
                        and "iget" in reg_state[service_reg].description
                    ):
                        unresolved_reason = UnresolvedReason.FIELD_BASED_SERVICE_OBJECT
                    else:
                        unresolved_reason = UnresolvedReason.CROSS_METHOD_SERVICE_OBJECT

                add_site = AddServiceCallSite(
                    dex_file=dex_file,
                    class_name=class_name,
                    method_name=method_name,
                    descriptor=descriptor,
                    instruction_offset=current_off,
                    server_register=server_reg,
                    service_register=service_reg,
                    is_service_resolved_locally=is_resolved_locally,
                    unresolved_reason=unresolved_reason,
                )
                add_service_sites.append(add_site)
                add_services_tracked.append((add_site, srv_val, current_off, op_name, inv_sig))

        # 5. Clobbering / other register-writing instructions
        elif op_name in _CLOBBERING_OPCODES and regs:
            dst_reg = regs[0]
            reg_state[dst_reg] = UnresolvedObject(op_name, current_off, dst_reg)

    # Correlate addService call sites with service constructions within this method
    matched_construction_offsets: Set[int] = set()

    for add_site, srv_val, add_off, add_op, add_sig in add_services_tracked:
        if isinstance(srv_val, GattServiceObject):
            matched_construction_offsets.add(srv_val.offset)
            matching_const_site = next(
                (cs for cs in construction_sites if cs.instruction_offset == srv_val.offset),
                None,
            )

            if srv_val.resolved_uuid is not None:
                # STRONG_STATIC_ASSOCIATION: Full verified register data-flow!
                final_step = TraceStep(
                    step_index=len(srv_val.trace_steps),
                    step_type="add_service_registration",
                    instruction_offset=add_off,
                    opcode=add_op,
                    details={
                        "method": add_sig,
                        "server_register": add_site.server_register,
                        "service_register": add_site.service_register,
                    },
                )
                full_trace = srv_val.trace_steps + [final_step]
                diagnosis = (
                    f"Verified intra-method registration: Literal UUID '{srv_val.resolved_uuid}' "
                    f"loaded at offset 0x{srv_val.trace_steps[0].instruction_offset:04x}, "
                    f"converted via UUID.fromString at offset 0x{srv_val.trace_steps[1].instruction_offset:04x}, "
                    f"used in BluetoothGattService constructor at offset 0x{srv_val.offset:04x}, "
                    f"and registered via BluetoothGattServer.addService() at offset 0x{add_off:04x}."
                )
                findings.append(
                    RegistrationFinding(
                        evidence_level=EvidenceLevel.STRONG_STATIC_ASSOCIATION,
                        normalized_uuid=srv_val.resolved_uuid,
                        dex_file=dex_file,
                        class_name=class_name,
                        method_name=method_name,
                        descriptor=descriptor,
                        diagnosis=diagnosis,
                        construction_site=matching_const_site,
                        registration_site=add_site,
                        trace_steps=full_trace,
                        unresolved_reason=None,
                    )
                )
            else:
                # Service constructed locally, but UUID could not be resolved to static literal
                diagnosis = (
                    f"Registration pattern detected: BluetoothGattServer.addService() called at offset 0x{add_off:04x} "
                    f"with locally constructed service (offset 0x{srv_val.offset:04x}), but the UUID passed to the "
                    f"service constructor could not be resolved to a static literal (parameter, field, or dynamic expression)."
                )
                findings.append(
                    RegistrationFinding(
                        evidence_level=EvidenceLevel.REGISTRATION_PATTERN_UUID_UNRESOLVED,
                        normalized_uuid=None,
                        dex_file=dex_file,
                        class_name=class_name,
                        method_name=method_name,
                        descriptor=descriptor,
                        diagnosis=diagnosis,
                        construction_site=matching_const_site,
                        registration_site=add_site,
                        trace_steps=srv_val.trace_steps,
                        unresolved_reason=UnresolvedReason.CROSS_METHOD_UUID,
                    )
                )
        else:
            # Service was NOT constructed in this method
            diagnosis = (
                f"Registration pattern detected: BluetoothGattServer.addService() invoked at offset 0x{add_off:04x}, "
                f"but the service object in register v{add_site.service_register} was not constructed locally within this method "
                f"(originates from method parameter, field read, or external method call)."
            )
            findings.append(
                RegistrationFinding(
                    evidence_level=EvidenceLevel.REGISTRATION_PATTERN_UUID_UNRESOLVED,
                    normalized_uuid=None,
                    dex_file=dex_file,
                    class_name=class_name,
                    method_name=method_name,
                    descriptor=descriptor,
                    diagnosis=diagnosis,
                    construction_site=None,
                    registration_site=add_site,
                    trace_steps=[],
                    unresolved_reason=add_site.unresolved_reason or UnresolvedReason.CROSS_METHOD_SERVICE_OBJECT,
                )
            )

    # Check for service constructions that were NOT passed to addService in this method
    for const_site in construction_sites:
        if const_site.instruction_offset not in matched_construction_offsets:
            uuid_display = const_site.resolved_uuid or "unresolved"
            diagnosis = (
                f"Service construction detected: BluetoothGattService constructor invoked at offset 0x{const_site.instruction_offset:04x} "
                f"with UUID '{uuid_display}', but BluetoothGattServer.addService() was not called within this method "
                f"(cross-method registration pattern or unused service)."
            )
            # Find matching trace steps
            matching_tracked = next(
                (srv for cs, srv in constructions_tracked if cs.instruction_offset == const_site.instruction_offset),
                None,
            )
            t_steps = matching_tracked.trace_steps if matching_tracked else []

            findings.append(
                RegistrationFinding(
                    evidence_level=EvidenceLevel.REGISTRATION_PATTERN_UUID_UNRESOLVED,
                    normalized_uuid=const_site.resolved_uuid,
                    dex_file=dex_file,
                    class_name=class_name,
                    method_name=method_name,
                    descriptor=descriptor,
                    diagnosis=diagnosis,
                    construction_site=const_site,
                    registration_site=None,
                    trace_steps=t_steps,
                    unresolved_reason=UnresolvedReason.SERVICE_CONSTRUCTED_WITHOUT_LOCAL_ADD_SERVICE,
                )
            )

    return findings, construction_sites, add_service_sites
