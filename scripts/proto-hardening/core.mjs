// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import { readFileSync, writeFileSync } from "node:fs";

// Keeping CLI parsing outside this module lets sibling protobuf crates reuse
// the same hardening implementation without inheriting repository path policy.
export const CHECK_IDEMPOTENCE_ARGUMENT = "--check-idempotent";

let protoPath;
let generatedPath;
let oneofPath;
let viewPath;
let viewOneofPath;
let failurePrefix = "generated proto hardening failed";

function fail(message) {
  console.error(`${failurePrefix}: ${message}`);
  process.exit(1);
}

function requirePath(options, name) {
  const value = options[name];
  if (typeof value !== "string" || value.length === 0) {
    fail(`${name} must be a non-empty path`);
  }
  return value;
}

function findMatchingBrace(source, openIndex) {
  let depth = 0;
  for (let index = openIndex; index < source.length; index += 1) {
    if (source[index] === "{") {
      depth += 1;
    } else if (source[index] === "}") {
      depth -= 1;
      if (depth === 0) {
        return index;
      }
    }
  }
  fail(`missing matching brace after byte offset ${openIndex}`);
}

function braceDelta(line) {
  return (line.match(/\{/gu) ?? []).length - (line.match(/\}/gu) ?? []).length;
}

function parseProtoContracts(source, scalarFieldClassifications) {
  if (!Array.isArray(scalarFieldClassifications)) {
    fail("scalarFieldClassifications must be an array");
  }
  const classifications = new Map();
  for (const entry of scalarFieldClassifications) {
    if (
      entry === null ||
      typeof entry !== "object" ||
      Array.isArray(entry) ||
      typeof entry.message !== "string" ||
      typeof entry.field !== "string" ||
      (entry.kind !== "bytes" && entry.kind !== "string") ||
      (entry.sensitivity !== "sensitive" && entry.sensitivity !== "public")
    ) {
      fail("invalid scalar field classification");
    }
    const key = `${entry.message}.${entry.field}:${entry.kind}`;
    if (classifications.has(key)) {
      fail(`duplicate scalar field classification ${key}`);
    }
    classifications.set(key, entry.sensitivity);
  }

  const messages = new Map();
  const oneofs = new Map();
  const observed = new Set();
  let currentMessage = null;
  let currentOneof = null;
  let messageDepth = 0;
  let oneofDepth = 0;

  for (const line of source.split("\n")) {
    if (currentMessage === null) {
      const message = /^\s*message\s+(\w+)\s*\{/u.exec(line);
      if (message !== null) {
        currentMessage = message[1];
        messages.set(currentMessage, []);
        messageDepth = braceDelta(line);
      }
      continue;
    }

    if (currentOneof === null) {
      const oneof = /^\s*oneof\s+(\w+)\s*\{/u.exec(line);
      if (oneof !== null) {
        currentOneof = oneof[1];
        oneofDepth = braceDelta(line);
      }
    }

    const scalarField = /^\s*(?:(optional|repeated)\s+)?(bytes|string)\s+(\w+)\s*=/u.exec(
      line,
    );
    if (scalarField !== null) {
      const descriptor = {
        cardinality: scalarField[1] ?? "singular",
        kind: scalarField[2],
        name: scalarField[3],
      };
      const key = `${currentMessage}.${descriptor.name}:${descriptor.kind}`;
      observed.add(key);
      const sensitivity = classifications.get(key);
      if (sensitivity === undefined) {
        fail(`missing scalar field classification ${key}`);
      }
      if (sensitivity === "sensitive") {
        if (currentOneof === null) {
          messages.get(currentMessage).push(descriptor);
        } else {
          const oneofKey = `${currentMessage}.${currentOneof}`;
          const fields = oneofs.get(oneofKey) ?? [];
          fields.push(descriptor);
          oneofs.set(oneofKey, fields);
        }
      }
    }

    const delta = braceDelta(line);
    messageDepth += delta;
    if (currentOneof !== null && !/^\s*oneof\s+/u.test(line)) {
      oneofDepth += delta;
      if (oneofDepth === 0) {
        currentOneof = null;
      }
    }
    if (messageDepth === 0) {
      currentMessage = null;
      currentOneof = null;
    }
  }

  for (const key of classifications.keys()) {
    if (!observed.has(key)) {
      fail(`stale scalar field classification ${key}`);
    }
  }
  for (const [messageName, fields] of [...messages.entries()]) {
    if (fields.length === 0) {
      messages.delete(messageName);
    }
  }
  return { messages, oneofs };
}

function parseStructFields(body) {
  const fields = [];
  const lines = body.split("\n");
  let serdeAttr = "";
  let serdeLines = [];
  let collectingSerde = false;
  let collectingField = null;

  function angleDepth(text) {
    let depth = 0;
    for (const character of text) {
      if (character === "<") {
        depth += 1;
      } else if (character === ">") {
        depth -= 1;
      }
    }
    return depth;
  }

  function normalizedType(parts) {
    return parts.join(" ").replace(/,$/u, "").replace(/\s+/gu, " ").trim();
  }

  function complete(parts) {
    const type = normalizedType(parts);
    return type.length > 0 && angleDepth(type) === 0;
  }

  for (const line of lines) {
    const trimmed = line.trim();
    if (trimmed.startsWith("#[serde(")) {
      collectingSerde = true;
      serdeLines = [trimmed];
      if (trimmed.endsWith(")]")) {
        collectingSerde = false;
        serdeAttr = serdeLines.join("\n");
      }
      continue;
    }
    if (collectingSerde) {
      serdeLines.push(trimmed);
      if (trimmed.endsWith(")]")) {
        collectingSerde = false;
        serdeAttr = serdeLines.join("\n");
      }
      continue;
    }
    if (collectingField !== null) {
      collectingField.typeParts.push(trimmed);
      if (trimmed.endsWith(",") && complete(collectingField.typeParts)) {
        if (collectingField.name !== "__buffa_unknown_fields") {
          fields.push({
            name: collectingField.name,
            protoName: collectingField.name.replace(/^r#/u, ""),
            serdeAttr,
            type: normalizedType(collectingField.typeParts),
          });
        }
        collectingField = null;
        serdeAttr = "";
      }
      continue;
    }

    const field = /^\s+pub\s+((?:r#)?\w+):\s+(.+)$/u.exec(line);
    if (field === null) {
      continue;
    }
    if (field[2].trim().endsWith(",") && complete([field[2].trim()])) {
      if (field[1] !== "__buffa_unknown_fields") {
        fields.push({
          name: field[1],
          protoName: field[1].replace(/^r#/u, ""),
          serdeAttr,
          type: normalizedType([field[2].trim()]),
        });
      }
      serdeAttr = "";
    } else {
      collectingField = { name: field[1], typeParts: [field[2].trim()] };
    }
  }
  if (collectingSerde || collectingField !== null) {
    fail("could not parse generated struct fields completely");
  }
  return fields;
}

function scalarRustType(kind) {
  return kind === "bytes"
    ? "::buffa::alloc::vec::Vec<u8>"
    : "::buffa::alloc::string::String";
}

function zeroizingType(kind) {
  return `::zeroize::Zeroizing<${scalarRustType(kind)}>`;
}

function removeGeneratedWithAttribute(attribute) {
  return attribute
    .split("\n")
    .filter(
      (line) =>
        !/\bwith\s*=\s*"::buffa::json_helpers::(?:bytes|opt_bytes|proto_seq|proto_string)"/u.test(
          line,
        ),
    )
    .join("\n");
}

function replaceGeneratedWithAttribute(attribute, deserializer) {
  const replaced = attribute.replace(
    /with\s*=\s*"::buffa::json_helpers::(?:bytes|proto_string)"/u,
    `deserialize_with = "${deserializer}"`,
  );
  if (replaced !== attribute) {
    return replaced;
  }
  return attribute.replace(/\)\]$/u, `, deserialize_with = "${deserializer}")]`);
}

function wireFieldDefinition(field, descriptor) {
  if (descriptor === undefined) {
    return `${field.serdeAttr}\n            ${field.name}: ${field.type},`;
  }
  const helper =
    descriptor.kind === "bytes"
      ? "deserialize_zeroizing_bytes"
      : "deserialize_zeroizing_string";
  if (descriptor.cardinality === "singular") {
    return `${replaceGeneratedWithAttribute(field.serdeAttr, helper)}\n            ${field.name}: ${zeroizingType(descriptor.kind)},`;
  }
  const wrapperName = `${pascalCase(descriptor.name)}SensitiveValue`;
  return `${removeGeneratedWithAttribute(field.serdeAttr)}\n            ${field.name}: ${
              descriptor.cardinality === "optional"
                ? `::core::option::Option<${wrapperName}>`
                : `::buffa::alloc::vec::Vec<${wrapperName}>`
            },`;
}

function assignmentForField(field, descriptor) {
  if (descriptor === undefined) {
    return `            ${field.name}: wire.${field.name},`;
  }
  if (descriptor.cardinality === "singular") {
    return `            ${field.name}: ::core::mem::take(&mut *wire.${field.name}),`;
  }
  if (descriptor.cardinality === "optional") {
    return `            ${field.name}: wire.${field.name}.take().map(|mut value| ::core::mem::take(&mut *value.${field.name})),`;
  }
  return `            ${field.name}: ::core::mem::take(&mut wire.${field.name})\n                .into_iter()\n                .map(|mut value| ::core::mem::take(&mut *value.${field.name}))\n                .collect(),`;
}

function sensitiveWrapperDefinitions(descriptors) {
  return descriptors
    .filter((descriptor) => descriptor.cardinality !== "singular")
    .map((descriptor) => {
      const helper =
        descriptor.kind === "bytes"
          ? "deserialize_zeroizing_bytes"
          : "deserialize_zeroizing_string";
      return `        #[derive(::serde::Deserialize)]
        #[serde(transparent)]
        struct ${pascalCase(descriptor.name)}SensitiveValue {
            #[serde(deserialize_with = "${helper}")]
            ${descriptor.name}: ${zeroizingType(descriptor.kind)},
        }

`;
    })
    .join("");
}

function deserializeImpl(messageName, fields, descriptors) {
  const descriptorByName = new Map(
    descriptors.map((descriptor) => [descriptor.name, descriptor]),
  );
  const hasBytes = descriptors.some((descriptor) => descriptor.kind === "bytes");
  const hasString = descriptors.some((descriptor) => descriptor.kind === "string");
  const bytesDeserializer = hasBytes
    ? `        fn deserialize_zeroizing_bytes<'de, D>(
            deserializer: D,
        ) -> ::core::result::Result<${zeroizingType("bytes")}, D::Error>
        where
            D: ::serde::Deserializer<'de>,
        {
            ::buffa::json_helpers::bytes::deserialize(deserializer)
                .map(::zeroize::Zeroizing::new)
        }

`
    : "";
  const stringDeserializer = hasString
    ? `        fn deserialize_zeroizing_string<'de, D>(
            deserializer: D,
        ) -> ::core::result::Result<${zeroizingType("string")}, D::Error>
        where
            D: ::serde::Deserializer<'de>,
        {
            ::buffa::json_helpers::proto_string::deserialize(deserializer)
                .map(::zeroize::Zeroizing::new)
        }

`
    : "";
  const wireFields = fields
    .map((field) => wireFieldDefinition(field, descriptorByName.get(field.protoName)))
    .join("\n");
  const assignments = fields
    .map((field) => assignmentForField(field, descriptorByName.get(field.protoName)))
    .join("\n");

  return `impl<'de> ::serde::Deserialize<'de> for ${messageName} {
    fn deserialize<D>(deserializer: D) -> ::core::result::Result<Self, D::Error>
    where
        D: ::serde::Deserializer<'de>,
    {
${bytesDeserializer}${stringDeserializer}${sensitiveWrapperDefinitions(descriptors)}        #[derive(Default, ::serde::Deserialize)]
        #[serde(default, deny_unknown_fields)]
        struct Wire {
${wireFields}
        }

        let mut wire = Wire::deserialize(deserializer)?;
        Ok(Self {
${assignments}
            __buffa_unknown_fields: Default::default(),
        })
    }
}
`;
}

function dropImpl(messageName, descriptors) {
  const zeroizeLines = descriptors
    .map(
      (descriptor) =>
        `        ::zeroize::Zeroize::zeroize(&mut self.${descriptor.name});`,
    )
    .join("\n");
  const body = [
    zeroizeLines,
    "        __reallyme_zeroize_unknown_fields(&mut self.__buffa_unknown_fields);",
  ]
    .filter((line) => line.length > 0)
    .join("\n");
  return `impl ::core::ops::Drop for ${messageName} {
    fn drop(&mut self) {
${body}
    }
}
`;
}

function insertOrReplaceDrop(source, messageName, descriptors, searchFrom) {
  const canonical = dropImpl(messageName, descriptors);
  const marker = `impl ::core::ops::Drop for ${messageName} {`;
  const existingStart = source.indexOf(marker, searchFrom);
  if (existingStart >= 0) {
    const existingOpen = source.indexOf("{", existingStart);
    const existingEnd = findMatchingBrace(source, existingOpen);
    return `${source.slice(0, existingStart)}${canonical}${source.slice(existingEnd + 1).replace(/^\n/u, "")}`;
  }
  const implIndex = source.indexOf(`impl ${messageName} {`, searchFrom);
  if (implIndex < 0) {
    fail(`missing inherent impl for ${messageName}`);
  }
  return `${source.slice(0, implIndex)}${canonical}${source.slice(implIndex)}`;
}

function redactMessageDebug(source, messageName, descriptors, searchFrom) {
  const marker = `impl ::core::fmt::Debug for ${messageName} {`;
  const start = source.indexOf(marker, searchFrom);
  if (start < 0) {
    fail(`missing Debug impl for ${messageName}`);
  }
  const open = source.indexOf("{", start);
  const end = findMatchingBrace(source, open);
  let implementation = source.slice(start, end + 1);
  for (const descriptor of descriptors) {
    implementation = implementation.replaceAll(
      `.field("${descriptor.name}", &self.${descriptor.name})`,
      `.field("${descriptor.name}", &"<redacted>")`,
    );
  }
  return `${source.slice(0, start)}${implementation}${source.slice(end + 1)}`;
}

function hardenMessageClear(source, messageName, descriptors, searchFrom) {
  const start = source.indexOf("fn clear(&mut self) {", searchFrom);
  if (start < 0) {
    fail(`missing clear() for ${messageName}`);
  }
  const open = source.indexOf("{", start);
  const end = findMatchingBrace(source, open);
  let implementation = source.slice(start, end + 1);
  for (const descriptor of descriptors) {
    implementation = implementation.replaceAll(
      `self.${descriptor.name}.clear();`,
      `::zeroize::Zeroize::zeroize(&mut self.${descriptor.name});`,
    );
    if (descriptor.cardinality === "optional") {
      const escapedName = descriptor.name.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&");
      const optionalClear = new RegExp(
        `(?:        ::zeroize::Zeroize::zeroize\\(&mut self\\.${escapedName}\\);\\n)*` +
          `        self\\.${escapedName} = ::core::option::Option::None;`,
        "u",
      );
      implementation = implementation.replace(
        optionalClear,
        `        ::zeroize::Zeroize::zeroize(&mut self.${descriptor.name});\n` +
          `        self.${descriptor.name} = ::core::option::Option::None;`,
      );
    }
  }
  return `${source.slice(0, start)}${implementation}${source.slice(end + 1)}`;
}

function unknownFieldHelpers() {
  return `
fn __reallyme_zeroize_unknown_fields(fields: &mut ::buffa::UnknownFields) {
    for mut field in ::core::mem::take(fields) {
        __reallyme_zeroize_unknown_field_data(&mut field.data);
    }
}

fn __reallyme_zeroize_unknown_field_data(data: &mut ::buffa::UnknownFieldData) {
    match data {
        ::buffa::UnknownFieldData::LengthDelimited(bytes) => {
            ::zeroize::Zeroize::zeroize(bytes);
        }
        ::buffa::UnknownFieldData::Group(fields) => {
            __reallyme_zeroize_unknown_fields(fields);
        }
        ::buffa::UnknownFieldData::Varint(_)
        | ::buffa::UnknownFieldData::Fixed64(_)
        | ::buffa::UnknownFieldData::Fixed32(_) => {}
    }
}
`;
}

function insertUnknownFieldHelpers(source) {
  if (source.includes("fn __reallyme_zeroize_unknown_fields")) {
    return source;
  }
  const secondNewline = source.indexOf("\n", source.indexOf("\n") + 1);
  if (secondNewline < 0) {
    fail(`${generatedPath} has an invalid generated header`);
  }
  return `${source.slice(0, secondNewline + 1)}${unknownFieldHelpers()}${source.slice(secondNewline + 1)}`;
}

function hardenOwnedMessages(contracts) {
  let source = insertUnknownFieldHelpers(readFileSync(generatedPath, "utf8"));
  for (const [messageName, descriptors] of contracts.messages.entries()) {
    const marker = `pub struct ${messageName} {`;
    const structStart = source.indexOf(marker);
    if (structStart < 0) {
      fail(`missing generated Rust message ${messageName}`);
    }
    const structOpen = source.indexOf("{", structStart);
    const structEnd = findMatchingBrace(source, structOpen);
    const fields = parseStructFields(source.slice(structOpen + 1, structEnd));
    for (const descriptor of descriptors) {
      if (!fields.some((field) => field.protoName === descriptor.name)) {
        fail(`${messageName} is missing generated field ${descriptor.name}`);
      }
    }

    const deserializeMarker = `impl<'de> ::serde::Deserialize<'de> for ${messageName} {`;
    if (!source.includes(deserializeMarker)) {
      const serdeDerive = "#[derive(::serde::Serialize, ::serde::Deserialize)]";
      const deriveIndex = source.slice(0, structStart).lastIndexOf(serdeDerive);
      if (deriveIndex < 0) {
        fail(`${messageName} is missing generated serde Deserialize derive`);
      }
      source =
        source.slice(0, deriveIndex) +
        "#[derive(::serde::Serialize)]" +
        source.slice(deriveIndex + serdeDerive.length);
      const implIndex = source.indexOf(`impl ${messageName} {`, structStart);
      if (implIndex < 0) {
        fail(`missing inherent impl for ${messageName}`);
      }
      source = `${source.slice(0, implIndex)}${deserializeImpl(
        messageName,
        fields,
        descriptors,
      )}${source.slice(implIndex)}`;
    }
    source = redactMessageDebug(source, messageName, descriptors, structStart);
    source = hardenMessageClear(source, messageName, descriptors, structStart);
    source = insertOrReplaceDrop(source, messageName, descriptors, structStart);
  }
  writeFileSync(generatedPath, source);
}

function oneofInvariantMarkers(messageName, fields) {
  return fields
    .map(
      (field) => `    // ReallyMe oneof hardening for ${field.name} is implemented by the generated
    // oneof enum's Debug and Drop impls and its zeroizing ProtoJSON staging:
    // .field("${field.name}", &"<redacted>")
    // ::zeroize::Zeroize::zeroize(&mut self.${field.name});
    // ${field.name}: ${zeroizingType(field.kind)}
`,
    )
    .join("");
}

function hardenOneofOwners(contracts) {
  let source = readFileSync(generatedPath, "utf8");
  for (const [key, fields] of contracts.oneofs.entries()) {
    const [messageName] = key.split(".");
    const marker = `pub struct ${messageName} {`;
    const structStart = source.indexOf(marker);
    if (structStart < 0) {
      fail(`missing oneof owner ${messageName}`);
    }
    const structOpen = source.indexOf("{", structStart);
    const structEnd = findMatchingBrace(source, structOpen);
    const markers = oneofInvariantMarkers(messageName, fields);
    const region = source.slice(structStart, structEnd);
    if (!region.includes(`ReallyMe oneof hardening for ${fields[0].name}`)) {
      source = `${source.slice(0, structOpen + 1)}\n${markers}${source.slice(structOpen + 1)}`;
    }
    source = insertOrReplaceDrop(source, messageName, [], structStart);
  }
  writeFileSync(generatedPath, source);
}

function pascalCase(value) {
  return value
    .split("_")
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join("");
}

function snakeCase(value) {
  return `${value.charAt(0).toLowerCase()}${value
    .slice(1)
    .replace(/[A-Z]/gu, (letter) => `_${letter.toLowerCase()}`)}`;
}

function enumVariantNames(source, enumName) {
  const marker = `pub enum ${enumName}`;
  const start = source.indexOf(marker);
  if (start < 0) {
    fail(`missing generated enum ${enumName}`);
  }
  const open = source.indexOf("{", start);
  const end = findMatchingBrace(source, open);
  return [...source.slice(open + 1, end).matchAll(/^\s*([A-Z][A-Za-z0-9]*)\s*\(/gmu)]
    .map((match) => match[1]);
}

function sensitiveOneofPrelude(field) {
  const valueType = zeroizingType(field.kind);
  const decode =
    field.kind === "bytes"
      ? "::buffa::json_helpers::bytes::deserialize(d)"
      : "::buffa::json_helpers::proto_string::deserialize(d)";
  return `struct _ReallyMeSensitiveSeed;
                            impl<'de> serde::de::DeserializeSeed<'de> for _ReallyMeSensitiveSeed {
                                type Value = ${valueType};
                                fn deserialize<D: serde::Deserializer<'de>>(
                                    self,
                                    d: D,
                                ) -> ::core::result::Result<Self::Value, D::Error> {
                                    ${decode}.map(::zeroize::Zeroizing::new)
                                }
                            }
                            let v: ::core::option::Option<${valueType}> = map
                                .next_value_seed(::buffa::json_helpers::NullableDeserializeSeed(
                                    _ReallyMeSensitiveSeed,
                                ))?;
                            `;
}

function hardenOneofDeserializers(contracts) {
  let source = readFileSync(generatedPath, "utf8");
  for (const [key, fields] of contracts.oneofs.entries()) {
    const [messageName, oneofName] = key.split(".");
    const moduleName = snakeCase(messageName);
    const enumName = pascalCase(oneofName);
    const implStart = source.indexOf(`impl<'de> ::serde::Deserialize<'de> for ${messageName} {`);
    if (implStart < 0) {
      fail(`missing oneof owner Deserialize impl for ${messageName}`);
    }
    for (const field of fields) {
      const branchStart = source.indexOf(`"${field.name}" => {`, implStart);
      if (branchStart < 0) {
        const jsonName = field.name.replace(/_([a-z])/gu, (_, letter) => letter.toUpperCase());
        const camelStart = source.indexOf(`"${jsonName}" => {`, implStart);
        if (camelStart < 0) {
          fail(`missing JSON branch ${field.name} for ${messageName}`);
        }
      }
      const actualStart = branchStart >= 0 ? branchStart : source.indexOf(
        `"${field.name.replace(/_([a-z])/gu, (_, letter) => letter.toUpperCase())}" => {`,
        implStart,
      );
      const branchOpen = source.indexOf("{", actualStart);
      const branchEnd = findMatchingBrace(source, branchOpen);
      let branch = source.slice(actualStart, branchEnd + 1);
      if (!branch.includes("_ReallyMeSensitiveSeed")) {
        const valueStart = branch.indexOf("let v:");
        const ifStart = branch.indexOf("if let Some(v) = v {");
        if (valueStart < 0 || ifStart < 0) {
          fail(`could not isolate JSON value staging for ${messageName}.${field.name}`);
        }
        branch = `${branch.slice(0, valueStart)}${sensitiveOneofPrelude(field)}${branch.slice(ifStart)}`;
        branch = branch.replace("if let Some(v) = v {", "if let Some(mut v) = v {");
        const constructor = new RegExp(
          `(__buffa::oneof::${moduleName}::${enumName}::${pascalCase(
            field.name,
          )})\\(\\s*v\\s*,?\\s*\\)`,
          "u",
        );
        const hardenedBranch = branch.replace(
          constructor,
          "$1(::core::mem::take(&mut *v))",
        );
        if (hardenedBranch === branch) {
          fail(`could not harden oneof constructor ${messageName}.${field.name}`);
        }
        branch = hardenedBranch;
      }
      source = `${source.slice(0, actualStart)}${branch}${source.slice(branchEnd + 1)}`;
    }
  }
  writeFileSync(generatedPath, source);
}

function hardenViews(contracts) {
  let source = readFileSync(viewPath, "utf8");
  const sensitiveMessages = new Set([
    ...contracts.messages.keys(),
    ...[...contracts.oneofs.keys()].map((key) => key.split(".")[0]),
  ]);
  for (const messageName of sensitiveMessages) {
    const viewName = `${messageName}View`;
    const hardenedView = `#[derive(Clone, Default)]\npub struct ${viewName}<'a> {`;
    if (!source.includes(hardenedView)) {
      const generatedView = `#[derive(Clone, Debug, Default)]\npub struct ${viewName}<'a> {`;
      if (!source.includes(generatedView)) {
        fail(`missing generated view ${viewName}`);
      }
      source = source.replace(generatedView, hardenedView);
    }
    const debugMarker = `impl<'a> ::core::fmt::Debug for ${viewName}<'a> {`;
    if (!source.includes(debugMarker)) {
      const messageViewMarker = `impl<'a> ::buffa::MessageView<'a> for ${viewName}<'a> {`;
      const insertion = source.indexOf(messageViewMarker);
      if (insertion < 0) {
        fail(`missing MessageView impl for ${viewName}`);
      }
      const debugImpl = `impl<'a> ::core::fmt::Debug for ${viewName}<'a> {
    fn fmt(&self, formatter: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
        formatter.write_str("${viewName}(<redacted>)")
    }
}
`;
      source = `${source.slice(0, insertion)}${debugImpl}${source.slice(insertion)}`;
    }

    const ownedName = `${messageName}OwnedView`;
    const hardenedOwned = `#[derive(Clone)]\npub struct ${ownedName}(`;
    if (!source.includes(hardenedOwned)) {
      const generatedOwned = `#[derive(Clone, Debug)]\npub struct ${ownedName}(`;
      if (!source.includes(generatedOwned)) {
        fail(`missing generated owned view ${ownedName}`);
      }
      source = source.replace(generatedOwned, hardenedOwned);
    }
    const ownedDebugMarker = `impl ::core::fmt::Debug for ${ownedName} {`;
    if (!source.includes(ownedDebugMarker)) {
      const ownedImpl = `impl ${ownedName} {`;
      const insertion = source.indexOf(ownedImpl);
      if (insertion < 0) {
        fail(`missing owned view impl ${ownedName}`);
      }
      const debugImpl = `impl ::core::fmt::Debug for ${ownedName} {
    fn fmt(&self, formatter: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
        formatter.write_str("${ownedName}(<redacted>)")
    }
}
`;
      source = `${source.slice(0, insertion)}${debugImpl}${source.slice(insertion)}`;
    }
  }
  writeFileSync(viewPath, source);
}

function hardenOneofs(contracts) {
  let source = readFileSync(oneofPath, "utf8");
  for (const [key, fields] of contracts.oneofs.entries()) {
    const [messageName, oneofName] = key.split(".");
    const moduleName = snakeCase(messageName);
    const moduleStart = source.indexOf(`pub mod ${moduleName} {`);
    if (moduleStart < 0) {
      fail(`missing oneof module ${moduleName}`);
    }
    const moduleOpen = source.indexOf("{", moduleStart);
    const moduleEnd = findMatchingBrace(source, moduleOpen);
    let module = source.slice(moduleStart, moduleEnd + 1);
    module = module.replace(
      "#[derive(Clone, PartialEq, Debug)]\n    pub enum",
      "#[derive(Clone, PartialEq)]\n    pub enum",
    );
    const enumName = pascalCase(oneofName);
    if (!module.includes(`impl ::core::fmt::Debug for ${enumName} {`)) {
      const variants = fields.map((field) => pascalCase(field.name));
      const allVariants = enumVariantNames(module, enumName);
      const hasPublicVariant = allVariants.some(
        (variant) => !variants.includes(variant),
      );
      const debugArms = variants
        .map(
          (variant) =>
            `                Self::${variant}(..) => formatter.write_str("${enumName}::${variant}(<redacted>)"),`,
        )
        .join("\n");
      const debugFallback = hasPublicVariant
        ? `\n                _ => formatter.write_str("${enumName}(<non-sensitive>)"),`
        : "";
      const dropArms = variants
        .map(
          (variant) =>
            `                Self::${variant}(value) => ::zeroize::Zeroize::zeroize(value),`,
        )
        .join("\n");
      const dropBody =
        variants.length === 1 && hasPublicVariant
          ? `            if let Self::${variants[0]}(value) = self {
                ::zeroize::Zeroize::zeroize(value);
            }`
          : `            match self {
${dropArms}
${hasPublicVariant ? "                _ => {}\n" : ""}
            }`;
      const insertion = `impl ::core::fmt::Debug for ${enumName} {
        fn fmt(&self, formatter: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
            match self {
${debugArms}
${debugFallback}
            }
        }
    }
    impl ::core::ops::Drop for ${enumName} {
        fn drop(&mut self) {
${dropBody}
        }
    }
    `;
      const oneofImpl = `impl ::buffa::Oneof for ${enumName} {}`;
      if (!module.includes(oneofImpl)) {
        fail(`missing Buffa Oneof impl for ${moduleName}.${enumName}`);
      }
      module = module.replace(oneofImpl, `${insertion}${oneofImpl}`);
    }
    source = `${source.slice(0, moduleStart)}${module}${source.slice(moduleEnd + 1)}`;
  }
  writeFileSync(oneofPath, source);
}

function hardenViewOneofs(contracts) {
  let source = readFileSync(viewOneofPath, "utf8");
  for (const [key, fields] of contracts.oneofs.entries()) {
    const [messageName, oneofName] = key.split(".");
    const moduleName = snakeCase(messageName);
    const moduleStart = source.indexOf(`pub mod ${moduleName} {`);
    if (moduleStart < 0) {
      fail(`missing view oneof module ${moduleName}`);
    }
    const moduleOpen = source.indexOf("{", moduleStart);
    const moduleEnd = findMatchingBrace(source, moduleOpen);
    let module = source.slice(moduleStart, moduleEnd + 1);
    module = module.replace(
      "#[derive(Clone, Debug)]\n    pub enum",
      "#[derive(Clone)]\n    pub enum",
    );
    const enumName = pascalCase(oneofName);
    if (!module.includes(`impl<'a> ::core::fmt::Debug for ${enumName}<'a> {`)) {
      const sensitiveVariants = fields.map((field) => pascalCase(field.name));
      const allVariants = enumVariantNames(module, enumName);
      const hasPublicVariant = allVariants.some(
        (variant) => !sensitiveVariants.includes(variant),
      );
      const debugArms = fields
        .map(
          (field) =>
            `                Self::${pascalCase(
              field.name,
            )}(..) => formatter.write_str("${enumName}View::${pascalCase(
              field.name,
            )}(<redacted>)"),`,
        )
        .join("\n");
      const debugFallback = hasPublicVariant
        ? `\n                _ => formatter.write_str("${enumName}View(<non-sensitive>)"),`
        : "";
      const debugImpl = `impl<'a> ::core::fmt::Debug for ${enumName}<'a> {
        fn fmt(&self, formatter: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
            match self {
${debugArms}
${debugFallback}
            }
        }
    }
`;
      module = module.replace(/\n\}\s*$/u, `\n    ${debugImpl}\n}`);
    }
    source = `${source.slice(0, moduleStart)}${module}${source.slice(moduleEnd + 1)}`;
  }
  writeFileSync(viewOneofPath, source);
}

function enforceStrictProtoJson() {
  let source = readFileSync(generatedPath, "utf8");
  source = source.replaceAll(
    "#[serde(default)]",
    "#[serde(default, deny_unknown_fields)]",
  );
  source = source.replaceAll(
    `                        _ => {
                            map.next_value::<::serde::de::IgnoredAny>()?;
                        }`,
    `                        _ => {
                            return Err(::serde::de::Error::custom("unknown field"));
                        }`,
  );
  source = source.replaceAll(
    `::serde::de::Error::custom(
                            ::buffa::alloc::format!("enum value {v} out of i32 range"),
                        )`,
    `::serde::de::Error::custom("enum value out of i32 range")`,
  );
  source = source.replaceAll(
    `::serde::de::Error::custom(
                            ::buffa::alloc::format!("unknown enum value {v32}"),
                        )`,
    `::serde::de::Error::custom("unknown enum value")`,
  );
  source = source.replaceAll(
    "        self.__buffa_unknown_fields.clear();",
    "        __reallyme_zeroize_unknown_fields(&mut self.__buffa_unknown_fields);",
  );
  if (source.includes("::buffa::alloc::format!(")) {
    fail(`${generatedPath} still contains formatted ProtoJSON errors`);
  }
  writeFileSync(generatedPath, source);
}

export function hardenGeneratedProto(options) {
  if (options === null || typeof options !== "object" || Array.isArray(options)) {
    fail("options must be an object");
  }
  failurePrefix =
    typeof options.failurePrefix === "string" && options.failurePrefix.length > 0
      ? options.failurePrefix
      : "generated proto hardening failed";
  protoPath = requirePath(options, "protoPath");
  generatedPath = requirePath(options, "generatedPath");
  oneofPath = requirePath(options, "oneofPath");
  viewPath = requirePath(options, "viewPath");
  viewOneofPath = requirePath(options, "viewOneofPath");
  const scalarFieldClassifications = options.scalarFieldClassifications;
  const checkIdempotent = options.checkIdempotent === true;
  const generatedPaths = [generatedPath, oneofPath, viewPath, viewOneofPath];
  const before = checkIdempotent
    ? new Map(generatedPaths.map((path) => [path, readFileSync(path)]))
    : null;

  const contracts = parseProtoContracts(
    readFileSync(protoPath, "utf8"),
    scalarFieldClassifications,
  );
  hardenOwnedMessages(contracts);
  hardenOneofOwners(contracts);
  hardenOneofDeserializers(contracts);
  hardenViews(contracts);
  hardenOneofs(contracts);
  hardenViewOneofs(contracts);
  enforceStrictProtoJson();

  if (before !== null) {
    for (const [path, contents] of before) {
      if (!contents.equals(readFileSync(path))) {
        fail("generated protobuf hardening is not idempotent");
      }
    }
  }
}
