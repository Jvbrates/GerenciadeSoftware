from typing import List, Dict, Tuple
from snmp_agent import snmp

def handle_request(req: snmp.SNMPRequest,
                   vbs: List[snmp.VariableBinding] | Dict[str, snmp.VariableBind]) -> Tuple[List[snmp.VariableBinding], int, int]:
    if isinstance(req.context, snmp.SnmpGetContext):
        if isinstance(vbs, dict):
            return get_req(req_vbs=req.variable_bindings, vbs=vbs)
        else:
            return get(req_vbs=req.variable_bindings, vbs=vbs)
    elif isinstance(req.context, snmp.SnmpGetNextContext):
        return get_next(req_vbs=req.variable_bindings, vbs=vbs)
    elif isinstance(req.context, snmp.SnmpGetBulkContext):
        return get_bulk(req_vbs=req.variable_bindings,
                           non_repeaters=req.non_repeaters,
                           max_repetitions=req.max_repetitions,
                           vbs=vbs)
    elif isinstance(req.context, snmp.SnmpSetRequestContext):
        return set_req(req_vbs=req.variable_bindings, vbs=vbs)
    else:
        raise NotImplementedError


def set_req(req_vbs: List[snmp.VariableBinding],
            vbs: Dict[str, snmp.VariableBind]) -> [List[snmp.VariableBinding], int, int]:
    response: List[snmp.VariableBinding] = []

    for index, var in enumerate(req_vbs):
        if binder := vbs.get(var.oid, None):
            if binder.access == snmp.VariableBind.Access.READ_ONLY:
                raise NotImplementedError("Implementar erro de tentativa de escrita em algo lido")
            print(f"INdex: {index}")
            err, value = binder.write(var)
            var.value = value
            response.append(var)

            if err != 0:
                print(f"SNMP ERROR {err}")
                return response, err, index
        else:
            print(vbs.keys())
            print(var.oid)
            raise NotImplementedError(f"Implementar exception para Valor nao encontrado, observe o get {var.oid}") #TODO

    return response, 0, 0


def get_req(req_vbs: List[snmp.VariableBinding], vbs: Dict[str, snmp.VariableBind]) \
        -> [List[snmp.VariableBinding], int, int]:
    response: List[snmp.VariableBinding] = []

    for index, vbind in enumerate(req_vbs):
        if binder := vbs.get(vbind.oid, None):
            err, value = binder.read(vbind)
            vbind.value = value
            response.append(vbind)

            if err != 0:
                print(f"SNMP ERROR {err}")
                return response, err, index
        else:
            print(vbs.keys())
            print(vbind.oid)
            raise NotImplementedError(f"Implementar exception para Valor nao encontrado, observe o get {vbind.oid}")

    return response, 0, 0

def get(req_vbs: List[snmp.VariableBinding],
        vbs: List[snmp.VariableBinding]) -> [List[snmp.VariableBinding], int, int]:
    results: List[snmp.VariableBinding] = []
    for req_vb in req_vbs:
        _results = [vb for vb in vbs if req_vb.oid == vb.oid]
        if _results:
            _result = _results[0]
        else:
            _result = snmp.VariableBinding(
                oid=req_vb.oid,
                value=snmp.NoSuchObject())
        results.append(_result)
    return results, 0, 0


def get_next(req_vbs: List[snmp.VariableBinding],
             vbs: List[snmp.VariableBinding]) -> [List[snmp.VariableBinding], int, int]:
    sorted_vbs = sorted(vbs, key=lambda x: [int(o) for o in x.oid.split('.')])
    results: List[snmp.VariableBinding] = []
    for req_vb in req_vbs:
        next_vb = snmp.VariableBinding(
            oid=req_vb.oid,
            value=snmp.EndOfMibView())
        for vb in sorted_vbs:
            if [int(o) for o in req_vb.oid.split('.')] < [int(o) for o in vb.oid.split('.')]:
                next_vb.oid = vb.oid
                next_vb.value = vb.value
                break
        results.append(next_vb)
    return results, 0, 0


def get_bulk(req_vbs: List[snmp.VariableBinding],
             non_repeaters: int,
             max_repetitions: int,
             vbs: List[snmp.VariableBinding]) -> [List[snmp.VariableBinding], int, int]:
    # non_repeaters
    _req_vbs = req_vbs[:non_repeaters]
    results = get_next(req_vbs=_req_vbs, vbs=vbs)
    # max_repetitions
    _req_vbs = req_vbs[non_repeaters:]
    for _ in range(max_repetitions):
        for index, req_vb in enumerate(_req_vbs):
            _results = get_next(req_vbs=[req_vb], vbs=vbs)
            _result = _results[0]
            results.append(_result)
            _req_vbs[index] = snmp.VariableBinding(
                oid=_result.oid,
                value=snmp.Null())
    return results, 0, 0
