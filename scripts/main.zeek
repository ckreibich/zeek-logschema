module Log::Schema;

export {
	## An individual field in a Zeek log, with all of its metadata.
	## Exporters may add to these fields and add their content via
	## hooks, see below. Fields start with an underscore when their
	## name collides with a reserved keyword. Running instances
	## through to_json() strips that prefix.
	type Field: record {
		name: string;  ##< Name of the field, as referred to in the log ("ts")
		_type: string;  ##< Zeek type of the field (e.g. "string", "addr", "bool").
		record_type: string;  ##< Record type containing this field (e.g. "Conn::Info", "conn_id").
		script: string;  ##< Script that defines the field, relative to the scripts folder (e.g. "base/init-bare.zeek").
		is_optional: bool;  ##< Whether the field is optional.
		_default: any &optional; ##< Default value of the field, if defined.
		docstring: string &optional;  ##< If available, the docstring for the field.
		package: string &optional;  ##< If part of a Zeek package, the package's name sans owner ("hello-world", not "zeek/hello-world").
	};

	## A Zeek log with its name and fields.
	type Log: record {
		name: string;  ##< Name of the log, in its short form (e.g. "conn").
		fields: table[string] of Field &ordered;  ##< Fields of that log.
	};

	## Schema-wide metadata, including all of the logs.
	type Info: record {
		zeek_version: string &default = zeek_version();

		## The logs, indexed by their Log::ID enum. The table is
		## ordered: traversing yields keys in case-insensitive,
		## alphabetical order.
		logs: table[Log::ID] of Log &ordered;
	};

	global field_hook: hook(id: Log::ID, field: Field);
	global log_hook: hook(id: Log::ID, log: Log);
	global schema_hook: hook(info: Info);
}

# Add the name of the field a record_field instance describes to itself:
redef record record_field += {
	name: string &optional;
};

# Given a record type name like "Conn::Info", returns a vector describing each
# of the fields that have a &log attribute. (Zeek handles record-level &log
# transparently for us.)
function get_record_fields(type_name: string): vector of record_field
	{
	# record_fields() provides detailed field info, while
	# record_type_to_vector() provides reliably ordered field names. Stitch
	# them together:
	local rfields_table = record_fields(type_name);
	local rfields = record_type_to_vector(type_name);
	local res: vector of record_field;

	for ( _, fieldname in rfields )
		{
		# We care only about fields that Zeek will log:
		if ( ! rfields_table[fieldname]$log )
			next;

		rfields_table[fieldname]$name = fieldname;
		res += rfields_table[fieldname];
		}

	return res;
	}

function unfold_field(rtype: string, fieldname: string, fieldinfo: record_field): vector of Field
	{
	local fields: vector of Field;

	# If the field is not a record, we just have a single field. Otherwise
	# we need to unfold the fields, potentially recursively, since each
	# loggable field becomes a single toplevel field in the log. Reliance on
	# the string representation of the type name is ugly.
	if ( starts_with(fieldinfo$type_name, "record ") )
		{
		local record_type_name = fieldinfo$type_name[7:];

		for ( _, rfield in get_record_fields(record_type_name) )
			{
			fields += unfold_field(
			    record_type_name,
			    cat(fieldname, ".", rfield$name),
			    rfield);
			}
		}
	else
		{
		# For example, "Conn::Info$ts":
		local qualified_fieldname = rtype + "$" + fieldinfo$name;

		local field = Field(
		    $name = fieldname,
		    $_type = fieldinfo$type_name,
		    $record_type = rtype,
		    $script = get_record_field_declaring_script(qualified_fieldname),
		    $is_optional = fieldinfo$optional);

		if ( fieldinfo?$default_val )
			field$_default = fieldinfo$default_val;

		local docstring = get_record_field_comments(qualified_fieldname);
		if ( |docstring| > 0 )
			field$docstring = docstring;

		# Take the directory in which a package's scripts reside to mean
		# the package name:
		if ( starts_with(field$script, "site/packages/") )
			field$package = split_string(field$script, /\//)[2];

		fields += field;
		}

	return fields;
	}

event analyze()
	{
	local logs: table[Log::ID] of Log &ordered;

	# Ensure we process the log streams in alphabetical order based on their
	# Log::ID enum vals, case-insensitively -- this isolates us from changes
	# in script load order.
	local id_map: table[string] of Log::ID;
	local ids: vector of string;
	local id: Log::ID;

	for ( id, _ in Log::active_streams )
		{
		ids += to_lower(cat(id));
		id_map[ids[-1]] = id;
		}

	sort(ids, strcmp);

	for ( _, idname in ids )
		{
		id = id_map[idname];

		local stream = Log::active_streams[id];
		local typ = cat(stream$columns);
		local fields: table[string] of Field = table() &ordered;
		local name: string;

		if ( stream?$path )
			name = stream$path;
		else
			{
			# For the unusual/broken case where we have no path, we
			# make one up from the record type's qualified name
			# (without the last part, which is usually "Info") and
			# hope it makes sense.
			local parts = split_string(typ, /::/);
			name = to_lower(join_string_vec(parts[0:-1], ""));
			}

		# Iterate over every field in the record type ...
		for ( _, rfield in get_record_fields(typ) )
			{
			# ... and expand it into the field(s) it turns into in
			# the log: this unfolds loggable record fields recursively.
			for ( _, field in unfold_field(typ, rfield$name, rfield) )
				{
				if ( hook field_hook(id, field) )
					fields[field$name] = field;
				}
			}

		local log = Log($name = name, $fields = fields);

		if ( hook log_hook(id, log) )
			logs[id] = log;
		}

	hook schema_hook(Info($logs = logs));
	}

event zeek_init()
	{
	# Run log stream analysis after all zeek_init handlers:
	schedule 0 sec { analyze() };
	}
