<!-- coderabbit-ai-generated:v1 -->

<!-- coderabbit-ai-generated-section:v1:a6d56385800380fa121b1b0d47bcbe8c171501d12a4801539dadd4f189970c53 -->

# Dependency license review

`dependency-licenses.json` records installed Python package metadata and frontend runtime entries in the lockfile. This is an inventory, not legal clearance. No missing metadata labels were found in the 70 audited Python and 122 frontend runtime entries. Developer-only frontend tools are outside that runtime inventory; preserve their package licenses as well.

The application repository retains the original MIT LICENSE and sidharth63 attribution. That license does not replace dependency licenses. Most runtime metadata declares MIT/BSD/Apache/ISC/PSF-style licenses. `certifi` declares MPL-2.0; `tqdm` declares MPL-2.0 AND MIT. `react-leaflet` 4.2.1 and `@react-leaflet/core` 2.1.0 declare **Hippocratic-2.1**, which carries use conditions beyond conventional permissive licenses. Review the installed package LICENSE files with your distribution/use requirements before release. Preserve relevant notices in redistributed builds; the JSON inventory is not a substitute for those license texts.

The inherited demonstration dataset and sample messages lack separately established authorship/redistribution provenance. Their checksum/source/labels are documented in `data/training/manifest.json`; obtain confirmation from the dataset owner or replace them with a verified corpus before operational distribution. No real customer messages were added during this task.

## Map dependency follow-up

Removed react-leaflet and @react-leaflet/core from the application and lockfile. The map now uses the existing Leaflet package directly, preserving explicit tile loading, markers, text-only popups and zoom controls. This removes those two Hippocratic-2.1 dependencies. Dataset provenance and remaining dependency notice obligations are still open.


<!-- /coderabbit-ai-generated:v1 -->