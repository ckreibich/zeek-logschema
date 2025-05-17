module Log::Schema::JSONSchema;

@load ../main

export {
	# A single property, in JSON Schema parlance: represents a log field.
	type Property: record {
		_type: string &optional;
		_enum: any &optional; # For enums; when used, _type is omitted
		_default: any &optional;
		description: string &optional;
	};

	# The JSON Schema representation of the schema data.
	type Export: record {
		schema: table[string] of any &ordered; # The JSON structure of the resulting schema
	};

	# Careful: ordering works only when initializing via table(), not {}.
	const schema_template: table[string] of any = table(
		["$schema"] = "https://json-schema.org/draft/2020-12/schema",
		["$id"] = "https://zeek.org/schema.json",
		["title"] = "",
		["description"] = "",
		["type"] = "object",
		["properties"] = "",
		["required"] = "",
	) &ordered &redef;

	## A filename to write each log's schema to. When this is "-" or empty,
	## the export writes all schemas to stdout, in alphabetical order, with
	## one line per schema. For supported substitutions, see
	## Log::Schema::create_filename().
	const filename = "zeek-{log}-log.schema.json" &redef;
}

# Tuck each log's resulting schema onto the Log record:
redef record Log::Schema::Log += {
	jsonschema_export: Export &optional;
};

function sorted_enum_names(typ: string): vector of string
	{
	local names: vector of string;

	for ( name in enum_names(typ) )
		names[|names|] = name;

	sort(names, strcmp);
	return names;
	}

function property_fill_type(prop: Property, typ: string)
	{
	if ( /^(set|vector)/ in typ )
		prop$_type = "array";
	else if ( typ == "count" || typ == "int" )
		prop$_type = "integer";
	else if ( typ == "port" )
		prop$_type ="integer";
	else if ( typ == "double" || typ == "interval" )
		prop$_type ="number";
	else if ( typ == "string" || typ == "addr" || typ == "subnet" || typ == "pattern" )
		prop$_type ="string";
	else if ( typ == "bool" )
		prop$_type ="boolean";
	else if ( typ == "time" )
		prop$_type ="number";
	else if ( /^enum / in typ )
		{
		# We handle enums specially: they list their possible values.
		# _type is best not used in this case, according to:
		# https://www.learnjsonschema.com/2020-12/validation/enum/
		# typ here is "enum <type>", e.g. "enum transport_proto".
		prop$_enum = sorted_enum_names(split_string1(typ, / /)[1]);
		}
	else
		Reporter::warning(fmt("Unexpected type string for JSON Schema mapping: %s", typ));
	}

function process_log(ex: Log::Schema::Exporter, log: Log::Schema::Log)
	{
	local schema = copy(schema_template);
	schema["title"] = fmt("Schema for Zeek %s.log", log$name);
	schema["description"] = fmt(
	    "JSON Schema for Zeek %s.log, version %s",
	    log$name, ex$zeek_version);

	local properties: table[string] of Property = table() &ordered;
	local required: vector of string = vector();

	for ( _, field in log$fields )
		{
		local prop = Property();

		property_fill_type(prop, field$_type);

		if ( field?$docstring )
			prop$description = field$docstring;
		if ( field?$_default )
			prop$_default = field$_default;
		if ( !field$is_optional )
			required += field$name;

		# There are various features in JSON Schema that are
		# hard to cover here, like minItems, uniqueItems, that
		# are not explicitly captured in Zeek's log Info
		# records, so we skip those here. Some might be
		# universally true and we could set them here, for all
		# properties.

		properties[field$name] = prop;
		}

	schema["properties"] = properties;
	schema["required"] = required;

	log$jsonschema_export = Export($schema=schema);
	}

function write_all_schemas(hdl: file, ex: Log::Schema::Exporter, logs: Log::Schema::LogsTable)
	{
	for ( _, log in logs )
		{
		write_file(hdl, to_json(log$jsonschema_export$schema));
		}
	}

function write_single_schema(hdl: file, ex: Log::Schema::Exporter, log: Log::Schema::Log)
	{
	write_file(hdl, to_json(log$jsonschema_export$schema));
	}

event zeek_init()
	{
	Log::Schema::add_exporter(Log::Schema::Exporter(
	    $filename = filename,
	    $process_log = process_log,
	    $write_all_schemas = write_all_schemas,
	    $write_single_schema = write_single_schema,
	));
	}
