module Log::Schema::JSONSchema;

@load ../main

export {
	# A single property, in JSON Schema parlance: represents a log field.
	type Property: record {
		_type: string;
		description: string &optional;
	};

	# A minimal container in case we add things in addition to the table
	# later on.
	type Export: record {
		schemas: table[string] of string &ordered;
	};

	# We use this table as a template for schema results. Value type "any"
	# allows us to mix types (strings, vectors, records, etc), as in a JSON
	# object.
	global schema_template: table[string] of any = {
		["$schema"] = "https://json-schema.org/draft/2020-12/schema",
		["$id"] = "https://zeek.org/schema.json",
		["title"] = "",
		["description"] = "",
		["type"] = "object",
		["properties"] = "",
		["required"] = "",
	} &ordered;
}

redef record Log::Schema::Info += {
	jsonschema_export: Export &optional;
};

function map_type(typ: string): string
	{
	if ( /^(set|vector)/ in typ )
		return "array";
	if ( /^(count|int)/ in typ )
		return "integer";
	if ( /^(port)/ in typ )
		return "integer";
	if ( /^(double|interval)/ in typ )
		return "number";
	if ( /^(enum|string|addr|subnet|pattern)/ in typ )
		return "string";
	if ( /^(bool)/ in typ )
		return "boolean";
	if ( typ == "time" )
		return "number";

	Reporter::warning(fmt("Unexpected type string for JSON Schema mapping: %s", typ));
	return typ;
	}

hook Log::Schema::schema_hook(info: Log::Schema::Info)
	{
	local ex: Export = Export();

	for ( _, log in info$logs )
		{
		local schema = copy(schema_template);
		local properties: table[string] of Property = table() &ordered;
		local required: vector of string = vector();

		schema["title"] = fmt("Schema for Zeek %s.log", log$name);
		schema["description"] = fmt(
		    "JSON Schema for Zeek %s.log, version %s",
		    log$name, info$zeek_version);

		for ( _, field in log$fields )
			{
			local prop = Property($_type = map_type(field$typ));

			if ( field?$docstring )
				prop$description = field$docstring;
			if ( !field$is_optional )
				required += field$name;

			properties[field$name] = prop;
			}

		schema["properties"] = properties;
		schema["required"] = required;

		ex$schemas[log$name] = to_json(schema);
		}

	info$jsonschema_export = ex;
	}

hook Log::Schema::write_hook(info: Log::Schema::Info)
	{
	for ( _, schema in info$jsonschema_export$schemas )
		print schema;
	}
