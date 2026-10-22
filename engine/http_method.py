"""Own HTTP method facts and the response boundary after a method edit."""
import re
from bounds import metadata_size, METADATA_BYTES, text_size

HTTP_TOKEN = re.compile(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+\Z", re.ASCII)


def request_method(request):
    # The pinned SDK's public getter calls .upper(), while RequestData retains
    # the actual wire token. Observations and outgoing snapshots use raw facts.
    return request.data.method.decode('utf-8', 'surrogateescape')


def parse_method(value):
    if not isinstance(value, str) or not HTTP_TOKEN.fullmatch(value):
        raise ValueError('Method must be a nonempty ASCII HTTP token')
    return value


def import_framing(value):
    fields = {'frontend_method', 'effective_method', 'source_content_length', 'source_transfer_encoding'}
    if not isinstance(value, dict) or set(value) != fields:
        raise ValueError('Invalid edited-method response framing facts')
    frontend, upstream = parse_method(value['frontend_method']), parse_method(value['effective_method'])
    if frontend == 'HEAD' or upstream != 'HEAD':
        raise ValueError('Edited-method framing requires a non-HEAD client and HEAD effective method')
    result = {'frontend_method': frontend, 'effective_method': upstream}
    total = 0
    for key in ('source_content_length', 'source_transfer_encoding'):
        items = value[key]
        if not isinstance(items, list) or len(items) > 1024:
            raise ValueError('Invalid source response framing headers')
        for item in items:
            if not isinstance(item, str) or any(c in item for c in '\0\r\n'):
                raise ValueError('Invalid source response framing header value')
            total += text_size(item, 65536 - total - 4, 'Source response framing', metadata=True) + 4
        result[key] = list(items)
    return result


def normalize_response(flow):
    frontend = flow.metadata.get('lens_frontend_method')
    response = flow.response
    if (frontend is None or frontend == 'HEAD' or flow.request.method != 'HEAD' or response is None
            or response.status_code in (204, 304) or 'lens_method_framing' in flow.metadata):
        return
    # A local map or policy denial may legitimately provide a body for the
    # original non-HEAD client. Unknown content is not observed empty content.
    if response.raw_content != b'':
        return
    facts = import_framing({'frontend_method': frontend, 'effective_method': flow.request.method,
        'source_content_length': response.headers.get_all('content-length'),
        'source_transfer_encoding': response.headers.get_all('transfer-encoding')})
    cost = metadata_size({'lens_method_framing': facts}, METADATA_BYTES)
    # The upstream HEAD may advertise the length of a representation it did not
    # send. A non-HEAD frontend cannot reuse that length and wait for those bytes.
    # Preserve its pre-normalization fields separately from delivered framing.
    response.headers.pop('transfer-encoding', None)
    response.headers['content-length'] = '0'
    flow.metadata['lens_method_framing'] = facts
    flow.metadata['lens_har_metadata_bytes'] = flow.metadata.get('lens_har_metadata_bytes', 0) + cost
