# Synthetic SBOM demonstration

Import [medfusion-demo.cdx.json](medfusion-demo.cdx.json) into the dashboard's
Device SBOM tab. The published-catalog regression requires eight Medfusion
candidates for manufacturer Smiths Medical, with `partial product name` evidence.

This file is a training example, not an inventory of a real device. The listed
version demonstrates preservation in the report; matching does not evaluate
whether that version is affected. Show the source advisory and limitations when
reviewing findings. Changing the manufacturer to an unrelated organization should
remove these candidates.
