# Editable diagram sources

The four figures are supplied in `.svg` (editable vector) and `.png` and `.pdf` render formats. The authoritative sources for the **Level-1 DFD** and two **Attack Trees** are the `.svg` files. `DFD_00_Context.dot` is also provided as a Graphviz source matching the context figure. Use the rendered PDF/PNG of each figure as final design and evidence of the model, not proof of executed software tests.

**DFD flow conventions:** Where directional request/response pairs are close, the figure bundles F IDs; the report's flow dictionary specifies exact direction and payload. The native metadata helper is a separate subprocess, and the logical SQLite stores are not necessarily separate physical database instances.
