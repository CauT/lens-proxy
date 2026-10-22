"""Adapt paused-flow continue commands to the shared HTTP message edit owner."""
from message_edit import PreparedEdit, prepare_legacy_body_edit, prepare_request_edit, prepare_response_edit


def prepare_edit(flow, cmd):
    """Select one matching paused side without mutating the flow or resuming it."""
    new = [side for side in ("request", "response") if side + "_edit" in cmd]
    legacy = [side for side in ("request", "response") if side + "_body" in cmd]
    if len(new) + len(legacy) > 1:
        raise ValueError("Only one request_edit/response_edit or legacy body field is allowed")
    sides = new or legacy
    if not sides:
        return PreparedEdit()
    side = sides[0]
    if flow.metadata.get("lens_pause_stage") != side:
        raise ValueError(f"{side} editing is only allowed at its matching paused stage")
    message = getattr(flow, side)
    if message is None:
        raise ValueError(f"No {side} available")
    facts = {"request_method": flow.request.method,
             "frontend_method": flow.metadata.get("lens_frontend_method", flow.request.method)}
    if legacy:
        return prepare_legacy_body_edit(message, side, cmd[side + "_body"], **facts)
    if side == "request":
        return prepare_request_edit(message, cmd["request_edit"])
    return prepare_response_edit(message, cmd["response_edit"], **facts)
