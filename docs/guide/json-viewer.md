# Reading JSON in Lens

Choose **JSON** in a Request or Response body. Valid UTF-8 JSON opens in **Tree**:
expand objects/arrays, select a field, and inspect its value without scanning one
large block of text. Collapse the Headers section to make more room.

- **Tree** preserves source order and every repeated object member. Arrays show
  their indices; objects and arrays show member/item counts. Strings, numbers,
  booleans and null have distinct visual treatment. Long row values use an
  explicit ellipsis; copying retains the entire selected JSON value.
- **Pretty** provides indentation, syntax colors, line numbers and optional line
  wrapping. It preserves number spelling, key order and source string escapes.
- **Source** shows the original UTF-8 document, including its whitespace/BOM.
  It is a read-only view; the capture and exports are not changed.
- **Find key or value** searches decoded strings and member names, including
  collapsed branches. Previous/Next navigate matches and reveal their ancestors.
  Search is case-insensitive, debounced and limited to 256 Unicode scalars.
- **Copy JSON** offers the formatted document or original source. Select a row
  to copy its exact original JSON value or its RFC 6901 JSON Pointer. Root is the
  empty pointer; `/` and `~` inside member names become `~1` and `~0`.

Duplicate keys remain distinct rows. A pointer passing through a duplicate name
is ambiguous, so pointer copying is disabled there; value copying still works.
Large integers, exponent spelling, `-0`, and escaped strings are not converted
through floating-point numbers or a dictionary that removes duplicates.

Malformed, unsupported-encoding or truncated previews remain source/error text
with an explanation. Truncated input is never presented as a complete JSON tree.
Unpaired Unicode surrogates are outside this viewer's Unicode decoding support
and remain source text with an explicit reason. There is no permissive repair.

The existing 2 MiB preview bound remains. Structural viewing admits at most
50,000 nodes and 32 nested levels; formatted output is limited to 4 MiB. Limits
are enforced before further tree/output allocation. Save the complete captured
body when a preview is insufficient. These are viewer budgets, not an overall
application-memory guarantee.

## Design research

Reviewed official documentation on 2026-10-23:

| Reference | Relevant observation | Lens decision |
| --- | --- | --- |
| [Firefox Network response details](https://firefox-source-docs.mozilla.org/devtools-user/network_monitor/request_details/index.html) | Structured JSON and raw response inspection serve different tasks | Keep tree navigation and original source side by side as selectable modes |
| [Postman response tools](https://learning.postman.com/latest-v-12/docs/use/send-requests/response-data/responses) | Body inspection exposes format selection, search and raw data tools | Make reading/search/copy controls visible inside both message sides |
| [RFC 8259](https://www.rfc-editor.org/rfc/rfc8259) | Duplicate-name behavior and numeric precision differ across implementations | Preserve ordered source occurrences and numeric lexemes |
| [RFC 6901](https://www.rfc-editor.org/rfc/rfc6901) | Pointers escape reference tokens and cannot identify duplicate-name members unambiguously | Copy standard pointers; disclose ambiguity rather than invent identity |
| [AppKit NSOutlineView](https://developer.apple.com/documentation/appkit/nsoutlineview) | Native expandable data-source/delegate table | Use reusable native rows instead of creating one SwiftUI view per member |

These are documentation observations and original design decisions, not runtime
reverse-engineering claims about Firefox or Postman. No response content is sent
to a remote formatter or embedded third-party service.

One parser owns the node graph, exact source ranges, formatting spans and pointer
facts. Parsing/search run on the existing bounded rendering actor. The TextKit
viewer colors only visible character ranges; the outline reuses visible cells.
Switching request/response identities cancels superseded work. See
`scripts/test-json-viewer.sh` for executable representation and failure checks.
