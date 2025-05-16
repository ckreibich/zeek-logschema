##! Schema export for Apache Avro.
##!
##! For the spec, see: https://avro.apache.org/docs/1.11.1/specification/

module Log::Schema::Avro;

@load ../main

export {
	type Field: record {
		name: string;
		doc: string &optional;
		_type: string;
		_default: any &optional;

		# Not currently used but in spec:
		# order: string &default = "ignore";
	};

	type Record: record {
		name: string;
		namespace: string &optional;
		doc: string &optional;

		# Not currently used but in spec:
		# aliases: vector of string &optional;

		fields: vector of Field;
	};

	# The JSON/Avro-suitable representation of the schema info.
	type Export: record {
		schema: Record; # The toplevel record (in Avro parlance) of the schema.
	};

	## Each log's Avro record can have a namespace. The exporter uses the
	## following by default. Redef this to the empty string to omit.
	const namespace = "org.zeek.logs" &redef;

	## A filename to write each log's schema to. When this is "-" or empty,
	## the export writes all schemas to stdout, in alphabetical order, with
	## one line per schema. For supported substitutions, see
	## Log::Schema::create_filename().
	const filename = "zeek-{log}-log.avsc" &redef;
}

# Tuck each log's resulting schema onto the Log record:
redef record Log::Schema::Log += {
	avro_export: Export &optional;
};

function map_type(typ: string): string
	{
	if ( /^(set|vector)/ in typ )
		return "array";
	if ( typ == "count" || typ == "int" )
		return "long";
	if ( typ == "port" )
		return "int";
	if ( typ == "double" || typ == "interval" )
		return "double";
	if ( typ == "string" || typ == "addr" || typ == "subnet" || typ == "pattern" || /^enum / in typ )
		return "string";
	if ( typ == "bool" )
		return "boolean";
	if ( typ == "time" )
		return "double";

	Reporter::warning(fmt("Unexpected type string for Avro mapping: %s", typ));
	return typ;
	}

function process_log(ex: Log::Schema::Exporter, log: Log::Schema::Log)
	{
	local r = Record($name = log$name);
	local f: Field;

	if ( |namespace| > 0 )
		r$namespace = namespace;

	for ( _, field in log$fields )
		{
		f = Field($name = field$name, $_type = map_type(field$_type));
		if ( field?$_default )
			f$_default = field$_default;
		if ( field?$docstring )
			f$doc = field$docstring;

		r$fields += f;
		}

	log$avro_export = Export($schema=r);
	}

function write_all_schemas(hdl: file, ex: Log::Schema::Exporter, logs: Log::Schema::LogsTable)
	{
	for ( _, log in logs )
		{
		write_file(hdl, to_json(log$avro_export$schema));
		}
	}

function write_single_schema(hdl: file, ex: Log::Schema::Exporter, log: Log::Schema::Log)
	{
	write_file(hdl, to_json(log$avro_export$schema));
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
