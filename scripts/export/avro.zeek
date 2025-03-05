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

	# A more JSON-suitable representation of the schema info.
	type Export: record {
		schema: Record; # The toplevel record of the schema.
	};

	## Each log's Avro record can have a namespace. The exporter uses the
	## following by default. Redef this to the empty string to omit.
	const namespace = "org.zeek.logs" &redef;

	## A file name to write each log's schema to. When this is empty or "-",
	## the export writes all schemas to stdout, in alphabetical order, with
	## one line per schema.
	const filename_template = "zeek-%l-log.avsc" &redef;
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
	if ( typ == "enum" || typ == "string" || typ == "addr" || typ == "subnet" || typ == "pattern" )
		return "string";
	if ( typ == "bool" )
		return "boolean";
	if ( typ == "time" )
		return "double";

	Reporter::warning(fmt("Unexpected type string for Avro mapping: %s", typ));
	return typ;
	}

hook Log::Schema::schema_hook(info: Log::Schema::Info)
	{
	local r: Record;
	local f: Field;

	for ( _, log in info$logs )
		{
		r = Record($name = log$name);

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
	}

hook Log::Schema::write_hook(info: Log::Schema::Info)
	{
	local hdl: file;
	local filename: string;

	for ( _, log in info$logs )
		{
		if ( |filename_template| == 0 || filename_template == "-" )
			print to_json(log$avro_export$schema);
		else
			{
			hdl = open(Log::Schema::create_schema_filename(filename_template, info, log));
			write_file(hdl, to_json(log$avro_export$schema));
			close(hdl);
			}
		}
	}
