<!-- coderabbit-ai-generated:v1 -->

<!-- coderabbit-ai-generated-section:v1:dd2b3577198b16fedd7f9d670bba4c29741b73c8032daece96054f59fcb736ca -->

<!-- coderabbit-ai-generated-section:v1:a6d56385800380fa121b1b0d47bcbe8c171501d12a4801539dadd4f189970c53 -->

# Dependency license review

`dependency-licenses.json` records installed Python package metadata and frontend runtime entries in the lockfile. This is an inventory, not legal clearance. No missing metadata labels were found in the 71 inventoried Python and 120 frontend runtime entries. Developer-only frontend tools are outside that runtime inventory; preserve their package licenses as well.

The application repository retains the original MIT LICENSE and sidharth63 attribution. That license does not replace dependency licenses. Most runtime metadata declares MIT/BSD/Apache/ISC/PSF-style licenses. `certifi` declares MPL-2.0; `tqdm` declares MPL-2.0 AND MIT. The earlier Hippocratic-2.1 map wrappers have been removed; ARC verification adds authres 1.2.0, whose metadata declares Apache 2.0. Review the installed package LICENSE files with your distribution/use requirements before release. Preserve relevant notices in redistributed builds; the JSON inventory is not a substitute for those license texts.

The inherited demonstration dataset and sample messages lack separately established authorship/redistribution provenance. Their checksum/source/labels are documented in `data/training/manifest.json`; obtain confirmation from the dataset owner or replace them with a verified corpus before operational distribution. No real customer messages were added during this task.

## Map dependency follow-up

Removed react-leaflet and @react-leaflet/core from the application and lockfile. The map now uses the existing Leaflet package directly, preserving explicit tile loading, markers, text-only popups and zoom controls. This removes those two Hippocratic-2.1 dependencies. Dataset provenance and remaining dependency notice obligations are still open.


<!-- /coderabbit-ai-generated:v1 -->