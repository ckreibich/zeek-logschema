module Log::Schema;

export {
	## An individual field in a Zeek log, with metadata known to Zeek.
	## Fields starting with an underscore avoid naming collisions with
	## reserved keywords, and simplify running through to_json() since it
	## can strip that prefix.
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
		name: string;  ##< Name of the log in its short form (e.g. "conn").
		fields: table[string] of Field &ordered;  ##< Fields of that log.

		# XXX The log record type (such as Conn::Info) may also have a
		# docstring, though in practice it's not particularly
		# useful. Could add here if desired.
	};

	# An alias for associating log streams with the exporters' view of logs.
	type LogsTable: table[Log::ID] of Log;

	## An Exporter groups the schema information and callbacks that process
	## it. Default implementations do nothing. Exporter implementations
	## redef this to associate needed state with it, and register instances
	## via Log::Schema::add_exporter().
	type Exporter: record {
		## For exporters that write to files (or stdout): the filename
		## pattern to use. This supports the substitutions of
		## Log::Schema::create_filename(). When the string uses per-log
		## patterns (e.g. "{log}"), the export will invoke the
		## write_single_log() callback for each log, with the resulting
		## filename. Otherwise, it will use write_all_logs(). When this
		## field is ommitted, the export invokes neither and instead
		## calls custom_export(), leaving outputting the result fully
		## to the exporter.
		filename: string &optional;

		## For some exporters, having the Zeek version is handy.
		zeek_version: string &default = zeek_version();
	};

	# redef here to make the Exporter type understandable to the callbacks.
	redef record Exporter += {
		## A callback for every Zeek log processed. Implementations can
		## hook their own per-log processing into the export at this
		## stage, for example to translate log information into an
		## alternative representation in line with their export format.
		process_log: function(ex: Exporter, log: Log)
		    &default = function(ex: Exporter, log: Log) {};

		## A callback to finalize schema state. Implementations can use
		## this to establish schema information across all logs in one
		## pass, or to make other final edits.
		finalize_schema: function(ex: Exporter, logs: LogsTable)
		    &default = function(ex: Exporter, logs: LogsTable) {};

		## A callback to write schema information for all logs to the
		## given file handle, as implied by the filename pattern in this
		## export. This runs after build_schema().
		write_all_schemas: function(hdl: file, ex: Exporter, logs: LogsTable)
		    &default = function(hdl: file, ex: Exporter, logs: LogsTable) {};

		## A callback to write schema information for a single log to the
		## given file handle, as implied by the filename pattern in this
		## export. This runs after build_schema().
		write_single_schema: function(hdl: file, ex: Exporter, log: Log)
		    &default = function(hdl: file, ex: Exporter, log: Log) {};

		## For some exporters file writes aren't the appropriate way to
		## report the schemas. When an Export instance does not set the
		## filename field, this callback gets invoked once instead of
		## write_all_schemas()/write_single_schema().
		custom_export: function(ex: Exporter, logs: LogsTable)
		    &default = function(ex: Exporter, logs: LogsTable) {};
	};

	## Registers the given exporter. Every exporter implementation needs
	## to call this, normally during zeek_init().
	global add_exporter: function(ex: Exporter);

	## This produces a filename from the given format string and additional
	## context. Supported substitutions in format:
	##
	## - "{log}": log name, such as "conn" for conn.log
	## - "{pid}": process ID
	## - "{ver}": Zeek version
	## - All of the strftime converters, such as %Y, %d, etc
	##
	## If format is the empty string the result is "-", implying stdout.
	global create_filename: function(format: string, ex: Exporter,
	    log: Log &default=Log($name="")): string;

	## Given a record type name like "Conn::Info", returns a vector
	## describing each of the fields. If log_only is true, only returns
	## fields that have a &log attribute. (Zeek handles record-level &log
	## transparently.)
	global get_record_fields: function(type_name: string,
	    log_only: bool &default=T): vector of record_field;

	## The log filter to use for determining the final logging setup, such
	## as included/excluded fields, log extensions, and field name mappings.
	## By default, this uses the "default" filter.
	const logfilter = "default" &redef;

	## Additional path prefixes to strip from the entries of the Field
	## record's "script" field. Note that the path leading up to (and
	## including) Zeek's own "scripts/" folder is always excluded (via
	## Zeekygen). Also, all of the prefixes listed here are tried in order,
	## so if multiple match iteratively, they will all get removed (i.e.,
	## prefixes "/foo" and "/bar", in that order, applied to "/foo/bar/baz"
	## will yield "/baz").
	const script_prefixes: vector of string &redef;
}

# Add the name of the field a record_field instance describes to itself:
redef record record_field += {
	name: string &optional;
};

# The registered list of exporters, built up by calls to add_exporter().
global exporters: vector of Exporter;

function get_record_fields(type_name: string, log_only: bool): vector of record_field
	{
	# record_fields() provides detailed field info, while
	# record_type_to_vector() provides reliably ordered field names. Stitch
	# them together:
	local rfields_table = record_fields(type_name);
	local rfields = record_type_to_vector(type_name);
	local res: vector of record_field;

	for ( _, fieldname in rfields )
		{
		if ( log_only && ! rfields_table[fieldname]$log )
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

		# If there are additional path prefixes to remove from the
		# identified script, do so now:
		if ( |field$script| > 0 )
			{
			for ( _, prefix in script_prefixes )
				{
				if ( starts_with(field$script, prefix) )
					field$script = field$script[|prefix|:];
				}
			}

		# Take the directory in which a package's scripts reside to mean
		# the package name:
		if ( starts_with(field$script, "site/packages/") )
			field$package = split_string(field$script, /\//)[2];

		fields += field;
		}

	return fields;
	}

# Process a single log stream, returning a Log record with all field info.
function analyze_stream(id: Log::ID): Log
	{
	local stream = Log::active_streams[id];
	local typ = cat(stream$columns);
	local fields: table[string] of Field = table() &ordered;
	local name: string;
	local filter: Log::Filter = Log::get_filter(id, logfilter);

	if ( filter$name == Log::no_filter$name )
		Reporter::warning(fmt("Log filter %s not found on log stream %s", logfilter, id));

	if ( stream?$path )
		name = stream$path;
	else if ( filter$name != Log::no_filter$name && filter?$path )
		name = filter$path;
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
			# Honor exclude/include sets in the filter:
			if ( filter$name != Log::no_filter$name )
				{
				if ( filter?$exclude && field$name in filter$exclude )
					next;
				if ( filter?$include && field$name !in filter$include )
					next;
				}

			# Honor field renaming in the filter:
			if ( field$name in filter$field_name_map )
				field$name = filter$field_name_map[field$name];

			fields[field$name] = field;
			}
		}

	if ( filter$name == Log::no_filter$name )
		return Log($name = name, $fields = fields);

	# Honor log extension fields in the filter.
	#
	# Ugly: we need to discern the default Log::default_ext_func (which
	# returns nothing) from a redef'd one (that should return a record). The
	# type_name() output for the default is "function(path:string) : void".
	#
	# Using the returned value itself is prone to running into "value used
	# but not set" interpreter errors.
	if ( split_string(type_name(filter$ext_func), / *: */)[-1] == "void" )
		return Log($name = name, $fields = fields);

	local extrec_type = type_name(filter$ext_func(name));

	for ( _, rfield in get_record_fields(extrec_type) )
		{
		for ( _, field in unfold_field(extrec_type, rfield$name, rfield) )
			{
			# Factor in the filter's extension prefix (often "_")
			# for the field name. Do this after the above
			# unfold_field(), since the latter does not know the
			# field-naming prefix mechanism.
			field$name = filter$ext_prefix + field$name;

			fields[field$name] = field;
			}
		}

	return Log($name = name, $fields = fields);
	}

function add_exporter(ex: Exporter)
	{
	exporters += ex;
	}

function is_single_log_filename(format: string): bool
	{
	return "{log}" in format;
	}

function create_filename(format: string, ex: Exporter, log: Log): string
	{
	local res = format;

	if ( |res| == 0 )
		res = "-";
	else
		{
		res = gsub(res, /\{log\}/, log$name);
		res = gsub(res, /\{pid\}/, cat(getpid()));
		res = gsub(res, /\{ver\}/, ex$zeek_version);
		res = strftime(res, network_time());
		}

	return res;
	}

event analyze()
	{
	local logs: LogsTable;
	local log: Log;

	# Ensure we process the log streams in alphabetical order based on their
	# Log::ID enum vals, case-insensitively -- this isolates us from changes
	# in script load order.
	local id_map: table[string] of Log::ID;
	local ids: vector of string;
	local id: Log::ID;
	local hdl: file;

	for ( id, _ in Log::active_streams )
		{
		ids += to_lower(cat(id));
		id_map[ids[-1]] = id;
		}

	sort(ids, strcmp);

	# Each registered exporter gets its own processing pass:
	for ( _, ex in exporters )
		{
		logs = table() &ordered;

		for ( _, idname in ids )
			{
			id = id_map[idname];
			log = analyze_stream(id);
			ex$process_log(ex, log);
			logs[id] = log;
			}

		ex$finalize_schema(ex, logs);

		if ( ex?$filename )
			{
			if ( is_single_log_filename(ex$filename) )
				{
				for ( _, log in logs )
					{
					hdl = open(create_filename(ex$filename, ex, log));
					ex$write_single_schema(hdl, ex, log);
					close(hdl);
					}
				}
			else
				{
				hdl = open(create_filename(ex$filename, ex));
				ex$write_all_schemas(hdl, ex, logs);
				close(hdl);
				}
			}
		else
			{
			ex$custom_export(ex, logs);
			}
		}
	}

event zeek_init()
	{
	# If we're runnign a cluster, do this only on the manager.
	if ( ! Cluster::is_enabled() || Cluster::local_node_type() == Cluster::MANAGER )
		{
		# Run log stream analysis after all zeek_init handlers:
		schedule 0 sec { analyze() };
		}
	}
