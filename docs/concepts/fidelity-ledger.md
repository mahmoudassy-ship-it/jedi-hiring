# Initial shell fidelity ledger

Reference: `legal-map-v1.png`
Desktop implementation: `legal-map-implementation-desktop.png`
Mobile implementation: `legal-map-implementation-mobile.png`

Checked at 1536 × 1024 and 390 × 844 on 2026-09-02.

| Comparison point | Concept evidence | Render evidence | Result |
| --- | --- | --- | --- |
| Header and navigation | Text brand followed by Legal map, Sources, Countries; active blue underline | Same labels, order, spacing model, and active treatment | Matched |
| First-view hierarchy | Editorial serif page title, one explanatory sentence, no hero or marketing CTA | Same exact title and explanatory copy with comparable scale and whitespace | Matched |
| Filters | One search field followed by four practical selects and a clear action | Same control anatomy, labels, order, borders, and responsive collapse | Matched |
| Overview strip | Three open metrics separated by hairlines with document, book, and globe icons | Same open strip and icon metaphors; values come from the live database | Matched; dynamic values are intentional |
| Main data surface | Open table with seven columns and official links beside summaries | Same column model, dividers, link placement, and source-first content | Matched |
| Palette and typography | True white, deep navy, restrained blue/teal, serif page title, sans-serif UI chrome | Same palette roles and type hierarchy; no gradients, cards, or visual filler | Matched |
| Responsive behavior | Desktop concept establishes table-led product shell | Mobile render preserves hierarchy, stacks filters and metrics, and contains table overflow | Matched extension |

## Intentional deviations

- Concept metrics were illustrative. The implementation shows the actual seed counts: 20 rules, 12 official sources, and 1 jurisdiction.
- Real legal summaries and stage labels are longer than the mockup examples, so fewer complete rows fit in the first desktop viewport.
- Pagination uses a compact current-page label until the dataset grows beyond one page; the API already supports multiple pages.
- The concept is an initial data-browser shell, not approval of a final visualization direction.

No unapproved marketing copy, decorative badges, gradients, card grids, or image assets were introduced.
