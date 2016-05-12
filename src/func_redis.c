/*
 * func_redis.c
 *
 * Original Author : Sergio Medina Toledo <lumasepa at gmail>
 * https://github.com/tic-ull/func_redis
 *
 * Contributor : Alan Graham <ag at zerohalo>
 * https://github.com/zerohalo/func_redis
 *
 * This program is free software, distributed under the terms of
 * the GNU General Public License Version 2. See the LICENSE file
 * at the top of the source tree.
 */

/*! \file
 *
 * \brief Functions for interaction with Redis database
 *
 * \author Sergio Medina Toledo <lumasepa at gmail>
 * \author Alan Graham <ag at zerohalo>
 *
 * \ingroup functions
 */

/*** MODULEINFO
	<support_level>extended</support_level>
	<depend>hiredis</depend>
 ***/


#include <asterisk.h>

ASTERISK_FILE_VERSION("func_redis.c", "$Revision: 6 $")

#include <asterisk/module.h>
#include <asterisk/channel.h>
#include <asterisk/pbx.h>
#include <asterisk/utils.h>
#include <asterisk/app.h>
#include <asterisk/cli.h>
#include <asterisk/config.h>

#ifndef AST_MODULE
#define AST_MODULE "func_redis"
#endif

#include <hiredis/hiredis.h>
#include <errno.h>

#if HIREDIS_MAJOR == 0 && HIREDIS_MINOR == 11
typedef char *sds;
struct sdshdr {
    int len;
    int free;
    char buf[];
};
void sdsfree(sds s) {
    if (s == NULL) return;
    free((char*)s - sizeof(struct sdshdr));
}
#endif

/*** DOCUMENTATION
	<function name="REDIS" language="en_US">
		<synopsis>
			Read from or write to a Redis database.
		</synopsis>
		<syntax>
			<parameter name="key" required="true" />
		</syntax>
		<description>
			<para>This function will read from or write a value to the Redis database.  On a
			read, this function returns the corresponding value from the database, or blank
			if it does not exist.  Reading a database value will also set the variable
			REDIS_RESULT.  If you wish to find out if an entry exists, use the REDIS_EXISTS
			function.</para>
		</description>
		<see-also>
			<ref type="function">REDIS_DELETE</ref>
			<ref type="function">REDIS_EXISTS</ref>
		</see-also>
	</function>
	<function name="REDIS_EXISTS" language="en_US">
		<synopsis>
			Check to see if a key exists in the Redis database.
		</synopsis>
		<syntax>
			<parameter name="key" required="true" />
		</syntax>
		<description>
			<para>This function will check to see if a key exists in the Redis
			database. If it exists, the function will return <literal>1</literal>. If not,
			it will return <literal>0</literal>.  Checking for existence of a database key will
			also set the variable REDIS_RESULT to the key's value if it exists.</para>
		</description>
		<see-also>
			<ref type="function">REDIS</ref>
		</see-also>
	</function>
	<function name="REDIS_DELETE" language="en_US">
		<synopsis>
			Return a value from the database and delete it.
		</synopsis>
		<syntax>
			<parameter name="key" required="true" />
		</syntax>
		<description>
			<para>This function will retrieve a value from the Redis database
			and then remove that key from the database.</para>
		</description>
	</function>
    <function name="REDIS_COMMAND" language="en_US">
		<synopsis>
			Send a command to redis, all redis commands are valid
		</synopsis>
		<syntax>
			<parameter name="channel" required="true" />
		</syntax>
		<description>
			<para>Send a command to redis, all redis commands are valid
			the result is saved in REDIS_RESULT, Example:
			REDIS_COMMAND("SET key value")
			</para>
		</description>
		<see-also>
			<ref type="function">REDIS</ref>
			<ref type="function">REDIS_DELETE</ref>
			<ref type="function">REDIS_EXISTS</ref>
		</see-also>
	</function>
 ***/

#define REDIS_CONF "func_redis.conf"
#define STR_CONF_SZ 256

// max size of long long [−9223372036854775807,+9223372036854775807]
#define LONG_LONG_LEN_IN_STR 20

#define __LOG_BUFFER_SZ 1024


#define redisLoggedCommand(redis, ...) redisCommand(redis, __VA_ARGS__); \
snprintf (__log_buffer, __LOG_BUFFER_SZ, __VA_ARGS__); \
ast_debug(1, "%s\n", __log_buffer);


#define get_safe_redis_context_for_func_as(name) redisContext * name = NULL;\
if (!(redis_context = ast_threadstorage_get(&redis_instance, sizeof(redisContext))))\
{\
ast_log(LOG_ERROR, "Error retrieving the redis context from thread\n");\
return -1;\
}\


#define get_safe_redis_context_for_cli_as(name) redisContext * name = NULL;\
if (!(redis_context = ast_threadstorage_get(&redis_instance, sizeof(redisContext))))\
{\
ast_log(LOG_ERROR, "Error retrieving the redis context from thread\n");\
return CLI_FAILURE;\
}\


#define replyHaveError(reply) (reply != NULL && reply->type == REDIS_REPLY_ERROR)

AST_MUTEX_DEFINE_STATIC(redis_lock);

static char hostname[STR_CONF_SZ] = "";
static char dbname[STR_CONF_SZ] = "";
static char password[STR_CONF_SZ] = "";
static char bgsave[STR_CONF_SZ] = "";
static unsigned int port = 6379;
static struct timeval timeout;
static char __log_buffer[__LOG_BUFFER_SZ] = "";

static int redis_connect(void * data);
static void redis_disconnect(void * data);

AST_THREADSTORAGE_CUSTOM(redis_instance, redis_connect, redis_disconnect)

/*!
 * \brief Handles the connection to redis, the auth and the selection of the database
 */
static int redis_connect(void * data)
{
    redisContext * redis_context = NULL;
    redis_context = redisConnectWithTimeout(hostname, port, timeout);
    if (redis_context == NULL) {
        ast_log(AST_LOG_ERROR,
                "Couldn't establish connection. Reason: UNKNOWN\n");
        return -1;
    }

    if(redis_context->err != 0){
        ast_log(AST_LOG_ERROR,
                "Couldn't establish connection. Reason: %s\n", redis_context->errstr);
        return -1;
    }

    redisReply * reply = NULL;
    if (strnlen(password, STR_CONF_SZ) != 0) {
        ast_log(AST_LOG_DEBUG, "REDIS : Authenticating...\n");
        reply = redisCommand(redis_context,"AUTH %s", password);
        if (replyHaveError(reply)) {
            ast_log(LOG_ERROR, "Unable to authenticate. Reason: %s\n", reply->str);
            return -1;
        }
        ast_log(AST_LOG_DEBUG, "REDIS : Authenticated.\n");
        freeReplyObject(reply);
    }

    if (strnlen(dbname, STR_CONF_SZ) != 0) {
        ast_log(AST_LOG_DEBUG, "Selecting DB %s\n", dbname);
        reply = redisLoggedCommand(redis_context,"SELECT %s", dbname);
        if (replyHaveError(reply)) {
            ast_log(AST_LOG_ERROR, "Unable to select DB %s. Reason: %s\n", dbname, reply->str);
            return -1;
        }
        ast_log(AST_LOG_DEBUG, "Database %s selected.\n", dbname);
        freeReplyObject(reply);
    }

    memcpy(data, redis_context, sizeof(redisContext));
    free(redis_context);
    return 0;
}

static void redis_disconnect(void *data){
    redisContext * redis_context = data;

    if (redis_context == NULL)
        return;

    if (redis_context->fd > 0)
        close(redis_context->fd);
    if (redis_context->obuf != NULL)
        sdsfree(redis_context->obuf);
    if (redis_context->reader != NULL){
        if (redis_context->reader->reply != NULL && redis_context->reader->fn && redis_context->reader->fn->freeObject)
            redis_context->reader->fn->freeObject(redis_context->reader->reply);
        if (redis_context->reader->buf != NULL)
            sdsfree(redis_context->reader->buf);
        free(redis_context->reader);
    } // = redisReaderFree(redis_context->reader);


#if HIREDIS_MAJOR == 0 && HIREDIS_MINOR > 12
    if (redis_context->tcp.host)
        free(redis_context->tcp.host);
    if (redis_context->tcp.source_addr)
        free(redis_context->tcp.source_addr);
    if (redis_context->timeout)
        free(redis_context->timeout);
#endif

#if HIREDIS_MAJOR == 0 && HIREDIS_MINOR == 13 && HIREDIS_PATCH == 0
    if (redis_context->unix.path){
        free(redis_context->unix.path);
    }
#endif

#if HIREDIS_MAJOR == 0 && HIREDIS_MINOR == 13 && HIREDIS_PATCH > 0
    if (redis_context->unix_sock.path){
        free(redis_context->unix_sock.path);
    }
#endif

    free(redis_context);
    return;
}

/*!
 * \brief Method for get an string from a redis reply, it is a helper method
 */
static char * get_reply_value_as_str(redisReply *reply){
    char * value = NULL;
    if (reply != NULL){
        switch (reply->type){
            case REDIS_REPLY_NIL:
                value = (char*)malloc(4);
                snprintf(value, 4, "%s", "nil");
                break;
            case REDIS_REPLY_INTEGER:
                value = (char*)malloc(LONG_LONG_LEN_IN_STR);
                snprintf(value, LONG_LONG_LEN_IN_STR, "%lld", reply->integer);
                break;
            case REDIS_REPLY_STRING:
            case REDIS_REPLY_STATUS:
            case REDIS_REPLY_ERROR:
                value = (char*)malloc((size_t)reply->len + 1);
                snprintf(value, (size_t)(reply->len) + 1, "%s", reply->str);
                break;
            case REDIS_REPLY_ARRAY:
                for(size_t i = 0; i < reply->elements; ++i){
                    char * old_value = NULL;
                    redisReply * element = reply->element[i];

                    char * element_value = get_reply_value_as_str(element);
                    size_t element_sz = (size_t)element->len;

                    if (i == 0){
                        size_t value_sz = element_sz + 1 ; // 1 = "\0"
                        value = (char*)malloc(value_sz);
                        snprintf(value, value_sz, "%s", element_value);
                    }else{
                        old_value = value;
                        size_t old_value_sz = strlen(old_value);
                        size_t value_new_sz = old_value_sz + element_sz + 2; // 2  = comma + "\0"
                        value = (char*)malloc(value_new_sz);
                        snprintf(value, value_new_sz, "%s,%s", old_value, element_value);
                        free(old_value);
                    }
                }
                break;
            default:
                break;
        }
    } else {
        ast_log(AST_LOG_ERROR, "REDIS: reply is NULL \n");
        value = NULL;
    }
    return value;
}

/*!
 * \brief Handles the load of the config of the module
 */
static int load_config(void)
{
    struct ast_config *config;
    const char *conf_str;
    struct ast_flags config_flags = { 0 };

    config = ast_config_load(REDIS_CONF, config_flags);

    if (config == CONFIG_STATUS_FILEMISSING || config == CONFIG_STATUS_FILEINVALID) {
        ast_log(AST_LOG_ERROR, "Unable to load config %s\n", REDIS_CONF);
        return -1;
    }

    ast_mutex_lock(&redis_lock);

    if (!(conf_str = ast_variable_retrieve(config, "general", "hostname"))) {
        ast_log(AST_LOG_NOTICE,
                "No redis hostname, using localhost as default.\n");
        conf_str =  "127.0.0.1";
    }

    ast_copy_string(hostname, conf_str, sizeof(hostname));

    if (!(conf_str = ast_variable_retrieve(config, "general", "port"))) {
        ast_log(AST_LOG_NOTICE,
                "No redis port found, using 6379 as default.\n");
        conf_str = "6379";
    }

    port = (unsigned int)atoi(conf_str);

    if (!(conf_str = ast_variable_retrieve(config, "general", "database"))) {
        ast_log(AST_LOG_NOTICE,
                "Redis: No database found, using '0' as default.\n");
        conf_str =  "0";
    }

    ast_copy_string(dbname, conf_str, sizeof(dbname));

    if (!(conf_str = ast_variable_retrieve(config, "general", "password"))) {
        ast_log(AST_LOG_NOTICE,
                "No redis password found, disabling authentication.\n");
        conf_str =  "";
    }

    ast_copy_string(password, conf_str, sizeof(password));

    if (!(conf_str = ast_variable_retrieve(config, "general", "timeout"))) {
        ast_log(AST_LOG_NOTICE,
                "No redis timeout found, using 5 seconds as default.\n");
        conf_str = "5";
    }

    timeout.tv_sec = atoi(conf_str);

    if (!(conf_str = ast_variable_retrieve(config, "general", "bgsave"))) {
        ast_log(AST_LOG_NOTICE,
                "No bgsave setting found, using default of false.\n");
        conf_str =  "false";
    }

    ast_copy_string(bgsave, conf_str, sizeof(bgsave));

    ast_config_destroy(config);

    ast_verb(2, "Redis config loaded.\n");

    /* Done reloading. Release lock so others can now use driver. */
    ast_mutex_unlock(&redis_lock);

    return 1;
}

static int function_redis_command(struct ast_channel *chan, const char *cmd,
                                 char *parse, char *return_buffer, size_t rtn_buff_len)
{
    AST_DECLARE_APP_ARGS(args, AST_APP_ARG(command););

    return_buffer[0] = '\0';

    if (ast_strlen_zero(parse)) {
        ast_log(LOG_WARNING, "REDIS_COMMAND requires one argument, REDIS_COMMAND(<command>)\n");
        return -1;
    }

    AST_STANDARD_APP_ARGS(args, parse);

    if (args.argc != 1) {
        ast_log(AST_LOG_WARNING, "REDIS_COMMAND requires one argument, REDIS_COMMAND(<command>)\n");
        return -1;
    }

    redisReply * reply = NULL;
    get_safe_redis_context_for_func_as(redis_context);

    reply = redisLoggedCommand(redis_context, args.command);

    if (replyHaveError(reply)) {
        ast_log(AST_LOG_ERROR, "%s\n", reply->str);
        pbx_builtin_setvar_helper(chan, "REDIS_ERROR", reply->str);
        freeReplyObject(reply);
        return -1;
    } else {
        char* reply_str = get_reply_value_as_str(reply);
        if (reply_str){
            strncpy(return_buffer, reply_str, rtn_buff_len);
            free(reply_str);
        }else{
            pbx_builtin_setvar_helper(chan, "REDIS_ERROR", "Error in reply as str");
        }
    }
    pbx_builtin_setvar_helper(chan, "REDIS_RESULT", return_buffer);

    return 0;
}

static struct ast_custom_function redis_command_function = {
        .name = "REDIS_COMMAND",
        .read = function_redis_command,
        .read_max = 2,
};


static int function_redis_read(struct ast_channel *chan, const char *cmd,
                               char *parse, char *return_buffer, size_t rtn_buff_len)
{
    AST_DECLARE_APP_ARGS(args,
                         AST_APP_ARG(key);
    );

    return_buffer[0] = '\0';

    if (ast_strlen_zero(parse)) {
        ast_log(AST_LOG_WARNING, "REDIS requires one argument REDIS(<key>)\n");
        return -1;
    }

    AST_STANDARD_APP_ARGS(args, parse);

    redisReply * reply = NULL;
    if (args.argc != 1) {
        ast_log(AST_LOG_WARNING, "REDIS requires one argument REDIS(<key>)\n");
        return -1;
    }

    get_safe_redis_context_for_func_as(redis_context);

    reply = redisLoggedCommand(redis_context,"GET %s", args.key);
    if (replyHaveError(reply)) {
        ast_log(AST_LOG_ERROR, "%s\n", reply->str);
        pbx_builtin_setvar_helper(chan, "REDIS_ERROR", reply->str);
        freeReplyObject(reply);
        return -1;
    } else {
        char * value = get_reply_value_as_str(reply);
        if(value) {
            snprintf(return_buffer, rtn_buff_len, "%s", value);
            pbx_builtin_setvar_helper(chan, "REDIS_RESULT", value);
            free(value);
        }
        freeReplyObject(reply);
    }
    return 0;
}

static int function_redis_write(struct ast_channel *chan, const char *cmd, char *parse,
                                const char *value)
{
    AST_DECLARE_APP_ARGS(args,
                         AST_APP_ARG(key);
    );

    if (ast_strlen_zero(parse)) {
        ast_log(AST_LOG_WARNING, "REDIS requires an argument, REDIS(<key>)=<value>\n");
        return -1;
    }

    AST_STANDARD_APP_ARGS(args, parse);

    if (args.argc != 1) {
        ast_log(AST_LOG_WARNING, "REDIS requires one argument REDIS(<key>)=<value>\n");
        return -1;
    }

    redisReply * reply = NULL;
    get_safe_redis_context_for_func_as(redis_context);
    reply = redisLoggedCommand(redis_context,"SET %s %s", args.key, value);

    if (replyHaveError(reply)) {
        ast_log(AST_LOG_WARNING, "REDIS: Error writing value to database. Reason: %s\n", reply->str);
        pbx_builtin_setvar_helper(chan, "REDIS_ERROR", reply->str);
        freeReplyObject(reply);
        return -1;
    }

    freeReplyObject(reply);

    return 0;
}

static struct ast_custom_function redis_function = {
        .name = "REDIS",
        .read = function_redis_read,
        .write = function_redis_write,
};

static int function_redis_exists(struct ast_channel *chan, const char *cmd,
                                 char *parse, char *return_buffer, size_t rtn_buff_len)
{
    AST_DECLARE_APP_ARGS(args,
                         AST_APP_ARG(key);
    );

    return_buffer[0] = '\0';

    if (ast_strlen_zero(parse)) {
        ast_log(AST_LOG_WARNING, "REDIS_EXISTS requires one argument, REDIS(<key>)\n");
        return -1;
    }

    AST_STANDARD_APP_ARGS(args, parse);

    if (args.argc != 1) {
        ast_log(AST_LOG_WARNING, "REDIS_EXISTS requires one argument, REDIS(<key>)\n");
        return -1;
    }

    redisReply * reply = NULL;
    get_safe_redis_context_for_func_as(redis_context);
    reply = redisLoggedCommand(redis_context,"EXISTS %s", args.key);

    if(reply == NULL){
        ast_log(AST_LOG_ERROR, "Redis reply is NULL\n");
        pbx_builtin_setvar_helper(chan, "REDIS_ERROR", "Reply is NULL");
        return -1;
    }

    if (replyHaveError(reply)) {
        ast_log(LOG_ERROR, "%s\n", reply->str);
        pbx_builtin_setvar_helper(chan, "REDIS_ERROR", reply->str);
        freeReplyObject(reply);
        return -1;
    } else  if (reply->integer == 1){
		strncpy(return_buffer, "1", rtn_buff_len);
	} else if (reply->integer == 0){
        strncpy(return_buffer, "0", rtn_buff_len);
    } else {
        ast_log(AST_LOG_WARNING, "REDIS EXIST failed\n");
        strncpy(return_buffer, "0", rtn_buff_len);
    }
    pbx_builtin_setvar_helper(chan, "REDIS_RESULT", return_buffer);

    return 0;
}

static struct ast_custom_function redis_exists_function = {
        .name = "REDIS_EXISTS",
        .read = function_redis_exists,
        .read_max = 2,
};

static int function_redis_delete(struct ast_channel *chan, const char *cmd,
                                 char *parse, char *return_buffer, size_t rtn_buff_len)
{
    AST_DECLARE_APP_ARGS(args,
                         AST_APP_ARG(key);
    );

    return_buffer[0] = '\0';

    if (ast_strlen_zero(parse)) {
        ast_log(AST_LOG_WARNING, "REDIS_DELETE requires one argument REDIS_DELETE(<key>)\n");
        return -1;
    }

    AST_STANDARD_APP_ARGS(args, parse);

    redisReply * reply = NULL;

    if (args.argc != 1) {
        ast_log(AST_LOG_WARNING, "REDIS_DELETE requires one argument, REDIS_DELETE(<key>)\n");
        return -1;
    }
    get_safe_redis_context_for_func_as(redis_context);
    reply = redisLoggedCommand(redis_context,"DEL %s", args.key);

    if(reply == NULL) {
        ast_log(AST_LOG_ERROR, "Redis reply is NULL\n");
        pbx_builtin_setvar_helper(chan, "REDIS_ERROR", "Reply is NULL");
        return -1;
    }
    if (replyHaveError(reply)) {
        ast_log(AST_LOG_ERROR, "%s\n", reply->str);
        pbx_builtin_setvar_helper(chan, "REDIS_ERROR", reply->str);
        freeReplyObject(reply);
        return -1;
    } else if (reply->integer == 0){
       ast_log(AST_LOG_WARNING, "REDIS_DELETE: Key %s not found in database.\n", args.key);
    }

    freeReplyObject(reply);

    return 0;
}

/*!
 * \brief Wrapper to execute REDIS_DELETE from a write operation. Allows execution
 * even if live_dangerously is disabled.
 */
static int function_redis_delete_write(struct ast_channel *chan, const char *cmd, char *parse,
                                       const char *value)
{
    /* Throwaway to hold the result from the read */
    char return_buffer[128];
    return function_redis_delete(chan, cmd, parse, return_buffer, sizeof(return_buffer));
}

static struct ast_custom_function redis_delete_function = {
        .name = "REDIS_DELETE",
        .read = function_redis_delete,
        .write = function_redis_delete_write,
};

static char *handle_cli_redis_set(struct ast_cli_entry *e, int cmd, struct ast_cli_args *args)
{
    switch (cmd) {
        case CLI_INIT:
            e->command = "redis set";
            e->usage =
                    "Usage: redis set <key> <value>\n"
                            "       Creates an entry in the Redis database for a given key and value.\n";
            return NULL;
        case CLI_GENERATE:
            return NULL;
        default:break;
    }

    if (args->argc != 4){
        return CLI_SHOWUSAGE;
    }


    redisReply * reply = NULL;
    get_safe_redis_context_for_cli_as(redis_context)

    reply = redisLoggedCommand(redis_context,"SET %s %s", args->argv[2], args->argv[3]);
    if (reply == NULL){
        ast_cli(args->fd, "Redis error, reply is NULL\n");
    } else if (replyHaveError(reply)) {
        ast_cli(args->fd, "%s\n", reply->str);
        ast_cli(args->fd, "Redis database error.\n");
    } else {
        ast_cli(args->fd, "Redis database entry created.\n");
    }
    freeReplyObject(reply);
    return CLI_SUCCESS;
}

static char *handle_cli_redis_del(struct ast_cli_entry *e, int cmd, struct ast_cli_args *args)
{
    switch (cmd) {
        case CLI_INIT:
            e->command = "redis del";
            e->usage =
                    "Usage: redis del <key>\n"
                            "       Deletes an entry in the Redis database for a given key.\n";
            return NULL;
        case CLI_GENERATE:
            return NULL;
        default:break;
    }

    if (args->argc != 3){
        return CLI_SHOWUSAGE;
    }

    redisReply * reply = NULL;
    get_safe_redis_context_for_cli_as(redis_context);
    reply = redisLoggedCommand(redis_context,"DEL %s", args->argv[2]);
    if (reply == NULL){
        ast_cli(args->fd, "Redis error, reply is NULL\n");
    } else if (replyHaveError(reply)) {
        ast_cli(args->fd, "%s\n", reply->str);
        ast_cli(args->fd, "Redis database entry does not exist.\n");
    } else {
        ast_cli(args->fd, "Redis database entry removed.\n");
    }

    freeReplyObject(reply);
    return CLI_SUCCESS;
}

static char *handle_cli_redis_show(struct ast_cli_entry *e, int cmd, struct ast_cli_args *args)
{
    switch (cmd) {
        case CLI_INIT:
            e->command = "redis show";
            e->usage =
                    "Usage: redis show\n"
                            "   OR: redis show [pattern]\n"
                            "       Shows Redis database contents, optionally restricted\n"
                            "       to a pattern.\n"
                            "\n"
                            "		[pattern] pattern to match keys\n"
                            "		Examples :\n"
                            "			- h?llo matches hello, hallo and hxllo\n"
                            "			- h*llo matches hllo and heeeello\n"
                            "			- h[ae]llo matches hello and hallo, but not hillo\n";
            return NULL;
        case CLI_GENERATE:
            return NULL;
        default:break;
    }

    redisReply * reply = NULL;
    get_safe_redis_context_for_cli_as(redis_context);
	if (args->argc == 3) {
		/* key */
		reply = redisLoggedCommand(redis_context,"KEYS %s", args->argv[2]);
	} else if (args->argc == 2) {
		/* show all */
		reply = redisLoggedCommand(redis_context,"KEYS *");
	} else {
		return CLI_SHOWUSAGE;
	}

	unsigned int i = 0;
	redisReply * get_reply;

    if (reply == NULL){
        ast_cli(args->fd, "Redis error, reply is NULL\n");
    } else if (replyHaveError(reply)) {
        ast_cli(args->fd, "%s\n", reply->str);
    } else {

        for (i = 0; i < reply->elements; i++) {
            get_reply = redisLoggedCommand(redis_context, "GET %s", reply->element[i]->str);
            if (get_reply != NULL) {
                if (replyHaveError(reply)) {
                    ast_cli(args->fd, "%s\n", reply->str);
                } else {
                    char *value = get_reply_value_as_str(get_reply);
                    if (value) {
                        ast_cli(args->fd, "%-50s: %-25s\n", reply->element[i]->str, value);
                        free(value);
                    }
                }
            }
            freeReplyObject(get_reply);
        }

        ast_cli(args->fd, "%d results found.\n", (int) reply->elements);
    }
    freeReplyObject(reply);

    return CLI_SUCCESS;
}

static struct ast_cli_entry cli_func_redis[] = {
        AST_CLI_DEFINE(handle_cli_redis_show, "Get all Redis values or by pattern in key"),
        AST_CLI_DEFINE(handle_cli_redis_del, "Delete a key - value in Redis"),
        AST_CLI_DEFINE(handle_cli_redis_set, "Creates a new key - value in Redis"),
};

static int unload_module(void)
{
    int res = 0;

    if (ast_true(bgsave)) {
        redisReply * reply = NULL;
        redisContext * redis_context = NULL;
        if (!(redis_context = ast_threadstorage_get(&redis_instance, sizeof(redisContext))))
        {
            ast_log(AST_LOG_ERROR, "Error retrieving the redis context from thread\n");
            return -1;
        }
        ast_log(AST_LOG_NOTICE, "Sending BGSAVE before closing connection.\n");
        reply = redisLoggedCommand(redis_context, "BGSAVE");
        ast_log(AST_LOG_NOTICE, "Closing connection.\n");
        freeReplyObject(reply);
    }

    ast_cli_unregister_multiple(cli_func_redis, ARRAY_LEN(cli_func_redis));
    res |= ast_custom_function_unregister(&redis_function);
    res |= ast_custom_function_unregister(&redis_exists_function);
    res |= ast_custom_function_unregister(&redis_delete_function);
    res |= ast_custom_function_unregister(&redis_command_function);

    return res;
}

static int load_module(void)
{
    if(load_config() == -1){
        return AST_MODULE_LOAD_DECLINE;
    }
    int res = 0;

    ast_cli_register_multiple(cli_func_redis, ARRAY_LEN(cli_func_redis));

    res |= ast_custom_function_register(&redis_function);
    res |= ast_custom_function_register(&redis_exists_function);
    res |= ast_custom_function_register(&redis_delete_function);
    res |= ast_custom_function_register(&redis_command_function);

    return res;
}

static int reload(void)
{
    ast_log(AST_LOG_NOTICE, "Reloading.\n");
    if(load_config() == -1){
        return AST_MODULE_LOAD_DECLINE;
    }
    return 0;
}

AST_MODULE_INFO(ASTERISK_GPL_KEY, AST_MODFLAG_DEFAULT, "Redis related dialplan functions",
                .load = load_module,
                .unload = unload_module,
                .reload = reload,
);
