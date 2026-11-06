# Ledger 0016: borrowed views given back to a frame-path caller (ADR-379)

`cl_borrow.src` is `@cl_borrow(node, cl_r + cl_r_first * 2^32)`, written by hand in view form. It takes the two
counts in one word, so it has four machine parameters. The register path lowers it, which already elides borrowed
views; the pre-0016 seed builds the compiler that has it, and its frame path would reject the function's own calls. `ws.awk` expands its
workspace loads and stores (`@LD`, `@ST`) into the clamp-and-scale pattern of the general program's views, and
`../0015/renumber.awk` numbers the result (`cl_borrow.view`).

- **Direct call.** It takes the callee's `borrowed` map (ADR-101, the views backend's `borrowed`). Each machine
  result the callee gives back as a borrowed view gets the frame slot of the operand it borrows: the frame-slot
  table (`T_FSLOT` of the analysis area) of the result takes the operand's slot. The result is 1, so the call is
  rejected, when the first machine result is borrowed or more than one machine result is left.
- **Any other call** keeps `1 < cl_r`.

`fr_call.awk` changes `fr_call`'s arity guard (B306: `1 < cl_r`) to `0 < @cl_borrow(...)`, which threads the state
the branch passes on. `fr_call`'s view is the same in the driver, the request and the x86-64 general program except
for callee handles. Each batch defines `@cl_borrow` with that store's `node_callee` and `borrowed` handles, then
`@fr_call` from that store's view, then `replace`s `fr_call`.

Why aliasing is enough:
- a borrowed result is the very pointer the call took (ADR-101);
- slots are per value and laid out before emission, so every later load of the result reads the operand's slot,
  and edges copy from it;
- RAX still goes to the first machine result. That is a non-borrowed value here, which the frame-path callee (its
  first machine return) and the register-path callee (its first non-borrowed return) agree on.
