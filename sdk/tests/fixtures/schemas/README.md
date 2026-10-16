# crJSON Schemas

`crJSON-schema.json` tracks the SDK's default/latest export shape, including
`isUpdateManifest` and `isCompressedManifest`.

`crJSON-2.4-schema.json` is the published C2PA 2.4 crJSON schema extracted from
the schema block in the [published crJSON specification](https://spec.c2pa.org/specifications/specifications/2.4/crJSON/crjson-format.html).
It is vendored byte-for-byte, including its lack of a trailing newline.
SHA-256:

```text
0cd7c0d554f9d3c388257688a361152a98c112fc9fc36a25e032972d7fc55613
```

The schema compliance tests pin these bytes and enable JSON Schema `format`
validation. The published schema forbids the two newer manifest flags. It is
kept separate from the SDK schema so changes to the default/latest format cannot
silently change the published 2.4 export contract.

Schema validation is not full C2PA conformance validation: in particular, the
published manifest wrapper allows arbitrary assertion contents. The export
profile does not revalidate claims or change `validationResults.specVersion`,
which identifies the native C2PA validator, not the serialization schema.
