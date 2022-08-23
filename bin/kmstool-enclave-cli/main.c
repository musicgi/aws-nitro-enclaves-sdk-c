#include <aws/nitro_enclaves/kms.h>
#include <aws/nitro_enclaves/nitro_enclaves.h>

#include <aws/common/command_line_parser.h>
#include <aws/common/encoding.h>
#include <aws/common/logging.h>

#include <json-c/json.h>

#include <linux/vm_sockets.h>
#include <sys/socket.h>

#include <errno.h>
#include <unistd.h>

#define DEFAULT_PROXY_PORT 8000
#define DEFAULT_REGION "us-east-1"
#define DEFAULT_PARENT_CID "3"

#define DECRYPT         0
#define GEN_RANDOM      1
#define GEN_DATA_KEY    2

enum status {
    STATUS_OK,
    STATUS_ERR,
};

#define fail_on(cond, msg)                                                                                             \
    if (cond) {                                                                                                        \
        if (msg != NULL) {                                                                                             \
            fprintf(stderr, "%s\n", msg);                                                                              \
        }                                                                                                              \
        return AWS_OP_ERR;                                                                                             \
    }

struct app_ctx {
    /* Allocator to use for memory allocations. */
    struct aws_allocator *allocator;
    /* KMS region to use. */
    const struct aws_string *region;
    /* vsock port on which to open service. */
    uint32_t port;
    /* vsock port on which vsock-proxy is available in parent. */
    uint32_t proxy_port;

    const struct aws_string *aws_access_key_id;
    const struct aws_string *aws_secret_access_key;
    const struct aws_string *aws_session_token;

    const struct aws_string *ciphertext_b64;
    uint32_t numberOfBytes;

    const struct aws_string *genKeyId;
    uint32_t genKeySpec;

    uint32_t reqCommand;

};

static void s_usage(int exit_code) {
    fprintf(stderr, "usage: kmstool_enclave_cli [options]\n");
    fprintf(stderr, "\n Options: \n\n");
    fprintf(stderr, "    --region REGION: AWS region to use for KMS\n");
    fprintf(stderr, "    --proxy-port PORT: Connect to KMS proxy on PORT. Default: 8000\n");
    fprintf(stderr, "    --aws-access-key-id ACCESS_KEY_ID: AWS access key ID\n");
    fprintf(stderr, "    --aws-secret-access-key SECRET_ACCESS_KEY: AWS secret access key\n");
    fprintf(stderr, "    --aws-session-token SESSION_TOKEN: Session token associated with the access key ID\n");

    fprintf(stderr, "    [Dcrypt] --ciphertext CIPHERTEXT: base64-encoded ciphertext that need to decrypt\n");

    fprintf(stderr, "    [GetRand] --numberOfBytes The length of the random byte string. This parameter is required.\n");

    fprintf(stderr, "    [GetDataKey] --keyId KEY_ID: key id (for symmetric keys)\n");
    fprintf(stderr, "    [GetDataKey] --keySpec KEY_ID: (for symmetric keys, is optional)\n");

    fprintf(stderr, "    [reqCommand] --reqCommand :  DECRYPT(1), GEN_RAND(2), GEN_DATA_KEY(3).\n");

    fprintf(stderr, "    --help: Display this message and exit\n");

    exit(exit_code);
}

static struct aws_cli_option s_long_options[] = {
    {"region", AWS_CLI_OPTIONS_REQUIRED_ARGUMENT, NULL, 'r'},
    {"proxy-port", AWS_CLI_OPTIONS_REQUIRED_ARGUMENT, NULL, 'x'},
    {"help", AWS_CLI_OPTIONS_NO_ARGUMENT, NULL, 'h'},
    {"aws-access-key-id", AWS_CLI_OPTIONS_REQUIRED_ARGUMENT, NULL, 'k'},
    {"aws-secret-access-key", AWS_CLI_OPTIONS_REQUIRED_ARGUMENT, NULL, 's'},
    {"aws-session-token", AWS_CLI_OPTIONS_REQUIRED_ARGUMENT, NULL, 't'},

    {"ciphertext", AWS_CLI_OPTIONS_OPTIONAL_ARGUMENT, NULL, 'c'},

    {"numberOfBytes", AWS_CLI_OPTIONS_REQUIRED_ARGUMENT, NULL, 'b'},

    {"keyId", AWS_CLI_OPTIONS_OPTIONAL_ARGUMENT, NULL, 'i'},
    {"keySpec", AWS_CLI_OPTIONS_OPTIONAL_ARGUMENT, NULL, 'e'},

    {"reqCommand", AWS_CLI_OPTIONS_OPTIONAL_ARGUMENT, NULL, 'd'},

    {NULL, 0, NULL, 0},
};

static void s_parse_options(int argc, char **argv, struct app_ctx *ctx) {
    ctx->proxy_port = DEFAULT_PROXY_PORT;
    ctx->region = NULL;
    ctx->aws_access_key_id = NULL;
    ctx->aws_secret_access_key = NULL;
    ctx->aws_session_token = NULL;
    ctx->ciphertext_b64 = NULL;

    while (true) {
        int option_index = 0;
        int c = aws_cli_getopt_long(argc, argv, "r:x:k:s:t:c:h:b:i:e:d", s_long_options, &option_index);
        if (c == -1) {
            break;
        }

        switch (c) {
            case 0:
                break;
            case 'r': {
                ctx->region = aws_string_new_from_c_str(ctx->allocator, aws_cli_optarg);
                break;
            }
            case 'x':
                ctx->proxy_port = atoi(aws_cli_optarg);
                break;
            case 'k':
                ctx->aws_access_key_id = aws_string_new_from_c_str(ctx->allocator, aws_cli_optarg);
                break;
            case 's':
                ctx->aws_secret_access_key = aws_string_new_from_c_str(ctx->allocator, aws_cli_optarg);
                break;
            case 't':
                ctx->aws_session_token = aws_string_new_from_c_str(ctx->allocator, aws_cli_optarg);
                break;
            case 'c':
                ctx->ciphertext_b64 = aws_string_new_from_c_str(ctx->allocator, aws_cli_optarg);
                break;

            case 'b':
                ctx->numberOfBytes = atoi(aws_cli_optarg);
                break;

            case 'i':
                ctx->genKeyId = aws_string_new_from_c_str(ctx->allocator, aws_cli_optarg);
                break;
            case 'e':
                ctx->genKeySpec = atoi(aws_cli_optarg);
                break;

            case 'd':
                ctx->reqCommand = atoi(aws_cli_optarg);
                break;

            case 'h':
                s_usage(0);
                break;
            default:
                fprintf(stderr, "Unknown option\n");
                s_usage(1);
                break;
        }
    }

    // Check if AWS access key ID is set
    if (ctx->aws_access_key_id == NULL) {
        fprintf(stderr, "--aws-access-key-id must be set\n");
        exit(1);
    }

    // Check if AWS secret access key is set
    if (ctx->aws_secret_access_key == NULL) {
        fprintf(stderr, "--aws-secret-access-key must be set\n");
        exit(1);
    }

    // Check if AWS session token is set
    if (ctx->aws_session_token == NULL) {
        fprintf(stderr, "--aws-session-token must be set\n");
        exit(1);
    }

    // Set default AWS region if not specified
    if (ctx->region == NULL) {
        ctx->region = aws_string_new_from_c_str(ctx->allocator, DEFAULT_REGION);
    }

    if(ctx->reqCommand == DECRYPT){
        // Check if ciphertext is set
        if (ctx->ciphertext_b64 == NULL) {
            fprintf(stderr, "--ciphertext must be set\n");
            exit(1);
        }

    }else if(ctx->reqCommand == GEN_RANDOM){

        if (ctx->numberOfBytes == NULL) {
            fprintf(stderr, "--numberOfBytes must be set\n");
            exit(1);
        }

    }else if(ctx->reqCommand == GEN_DATA_KEY){

        if (ctx->genKeyId == NULL) {
            fprintf(stderr, "--keyId must be set\n");
            exit(1);
        }

        if (ctx->genKeySpec != NULL) {
            if (ctx->genKeySpec == NULL) {
                fprintf(stderr, "--keySpec must be set if key-id exists\n");
                exit(1);
            }
        }
    }
}

static int decrypt(struct app_ctx *app_ctx, struct aws_byte_buf *ciphertext_decrypted_b64) {
    ssize_t rc = 0;

    struct aws_credentials *credentials = NULL;
    struct aws_nitro_enclaves_kms_client *client = NULL;

    /* Parent is always on CID 3 */
    struct aws_socket_endpoint endpoint = {.address = DEFAULT_PARENT_CID, .port = app_ctx->proxy_port};
    struct aws_nitro_enclaves_kms_client_configuration configuration = {
        .allocator = app_ctx->allocator, .endpoint = &endpoint, .domain = AWS_SOCKET_VSOCK, .region = app_ctx->region};

    /* Sets the AWS credentials and creates a KMS client with them. */
    struct aws_credentials *new_credentials = aws_credentials_new(
        app_ctx->allocator,
        aws_byte_cursor_from_c_str((const char *)app_ctx->aws_access_key_id->bytes),
        aws_byte_cursor_from_c_str((const char *)app_ctx->aws_secret_access_key->bytes),
        aws_byte_cursor_from_c_str((const char *)app_ctx->aws_session_token->bytes),
        UINT64_MAX);

    /* If credentials or client already exists, replace them. */
    if (credentials != NULL) {
        aws_nitro_enclaves_kms_client_destroy(client);
        aws_credentials_release(credentials);
    }

    credentials = new_credentials;
    configuration.credentials = new_credentials;
    client = aws_nitro_enclaves_kms_client_new(&configuration);

    /* Decrypt uses KMS to decrypt the ciphertext */
    /* Get decode base64 string into bytes. */
    size_t ciphertext_len;
    struct aws_byte_buf ciphertext;
    struct aws_byte_cursor ciphertext_b64 = aws_byte_cursor_from_c_str((const char *)app_ctx->ciphertext_b64->bytes);

    rc = aws_base64_compute_decoded_len(&ciphertext_b64, &ciphertext_len);
    fail_on(rc != AWS_OP_SUCCESS, "Ciphertext not a base64 string");
    rc = aws_byte_buf_init(&ciphertext, app_ctx->allocator, ciphertext_len);
    fail_on(rc != AWS_OP_SUCCESS, "Memory allocation error");
    rc = aws_base64_decode(&ciphertext_b64, &ciphertext);
    fail_on(rc != AWS_OP_SUCCESS, "Ciphertext not a base64 string");

    /* Decrypt the data with KMS. */
    struct aws_byte_buf ciphertext_decrypted;
    rc = aws_kms_decrypt_blocking(client, &ciphertext, &ciphertext_decrypted);
    aws_byte_buf_clean_up(&ciphertext);
    fail_on(rc != AWS_OP_SUCCESS, "Could not decrypt ciphertext");

    /* Encode ciphertext into base64 for printing out the result. */
    size_t ciphertext_decrypted_b64_len;
    struct aws_byte_cursor ciphertext_decrypted_cursor = aws_byte_cursor_from_buf(&ciphertext_decrypted);
    aws_base64_compute_encoded_len(ciphertext_decrypted.len, &ciphertext_decrypted_b64_len);
    rc = aws_byte_buf_init(ciphertext_decrypted_b64, app_ctx->allocator, ciphertext_decrypted_b64_len + 1);
    fail_on(rc != AWS_OP_SUCCESS, "Memory allocation error");
    rc = aws_base64_encode(&ciphertext_decrypted_cursor, ciphertext_decrypted_b64);
    fail_on(rc != AWS_OP_SUCCESS, "Base64 encoding error");
    aws_byte_buf_append_null_terminator(ciphertext_decrypted_b64);

    aws_nitro_enclaves_kms_client_destroy(client);
    aws_credentials_release(credentials);
    return AWS_OP_SUCCESS;
}

static int generateRandom(struct app_ctx *app_ctx, struct aws_byte_buf *output) {
    ssize_t rc = 0;

    struct aws_credentials *credentials = NULL;
    struct aws_nitro_enclaves_kms_client *client = NULL;

    /* Parent is always on CID 3 */
    struct aws_socket_endpoint endpoint = {.address = DEFAULT_PARENT_CID, .port = app_ctx->proxy_port};
    struct aws_nitro_enclaves_kms_client_configuration configuration = {
        .allocator = app_ctx->allocator, .endpoint = &endpoint, .domain = AWS_SOCKET_VSOCK, .region = app_ctx->region};

    /* Sets the AWS credentials and creates a KMS client with them. */
    struct aws_credentials *new_credentials = aws_credentials_new(
        app_ctx->allocator,
        aws_byte_cursor_from_c_str((const char *)app_ctx->aws_access_key_id->bytes),
        aws_byte_cursor_from_c_str((const char *)app_ctx->aws_secret_access_key->bytes),
        aws_byte_cursor_from_c_str((const char *)app_ctx->aws_session_token->bytes),
        UINT64_MAX);

    /* If credentials or client already exists, replace them. */
    if (credentials != NULL) {
        aws_nitro_enclaves_kms_client_destroy(client);
        aws_credentials_release(credentials);
    }

    credentials = new_credentials;
    configuration.credentials = new_credentials;
    client = aws_nitro_enclaves_kms_client_new(&configuration);

    /* generate the random with KMS. */
    struct aws_byte_buf ciphertext_decrypted;
    rc = aws_kms_generate_random_blocking(
        client, app_ctx->numberOfBytes, &ciphertext_decrypted);

    /* Encode ciphertext into base64 for printing out the result. */
    size_t output_len;
    struct aws_byte_cursor ciphertext_decrypted_cursor = aws_byte_cursor_from_buf(&ciphertext_decrypted);
    aws_base64_compute_encoded_len(ciphertext_decrypted.len, &output_len);
    rc = aws_byte_buf_init(output, app_ctx->allocator, output_len + 1);
    fail_on(rc != AWS_OP_SUCCESS, "Memory allocation error");
    rc = aws_base64_encode(&ciphertext_decrypted_cursor, output);
    fail_on(rc != AWS_OP_SUCCESS, "Base64 encoding error");
    aws_byte_buf_append_null_terminator(output);

    aws_nitro_enclaves_kms_client_destroy(client);
    aws_credentials_release(credentials);
    return AWS_OP_SUCCESS;
}

static int generateDataKey(struct app_ctx *app_ctx, struct aws_byte_buf *output) {
    ssize_t rc = 0;

    struct aws_credentials *credentials = NULL;
    struct aws_nitro_enclaves_kms_client *client = NULL;

    /* Parent is always on CID 3 */
    struct aws_socket_endpoint endpoint = {.address = DEFAULT_PARENT_CID, .port = app_ctx->proxy_port};
    struct aws_nitro_enclaves_kms_client_configuration configuration = {
        .allocator = app_ctx->allocator, .endpoint = &endpoint, .domain = AWS_SOCKET_VSOCK, .region = app_ctx->region};

    /* Sets the AWS credentials and creates a KMS client with them. */
    struct aws_credentials *new_credentials = aws_credentials_new(
        app_ctx->allocator,
        aws_byte_cursor_from_c_str((const char *)app_ctx->aws_access_key_id->bytes),
        aws_byte_cursor_from_c_str((const char *)app_ctx->aws_secret_access_key->bytes),
        aws_byte_cursor_from_c_str((const char *)app_ctx->aws_session_token->bytes),
        UINT64_MAX);

    /* If credentials or client already exists, replace them. */
    if (credentials != NULL) {
        aws_nitro_enclaves_kms_client_destroy(client);
        aws_credentials_release(credentials);
    }

    credentials = new_credentials;
    configuration.credentials = new_credentials;
    client = aws_nitro_enclaves_kms_client_new(&configuration);

    /* Decrypt uses KMS to decrypt the ciphertext */
    /* Get decode base64 string into bytes. */
    size_t ciphertext_len;
    struct aws_byte_buf plaintext;
    struct aws_byte_cursor ciphertext_b64 = aws_byte_cursor_from_c_str((const char *)app_ctx->ciphertext_b64->bytes);

    // rc = aws_base64_compute_decoded_len(&ciphertext_b64, &ciphertext_len);
    // fail_on(rc != AWS_OP_SUCCESS, "Ciphertext not a base64 string");
    rc = aws_byte_buf_init(&plaintext, app_ctx->allocator, ciphertext_len);
    fail_on(rc != AWS_OP_SUCCESS, "Memory allocation error");
    // rc = aws_base64_decode(&ciphertext_b64, &ciphertext);
    // fail_on(rc != AWS_OP_SUCCESS, "Ciphertext not a base64 string");

    /* generate the data key with KMS. */
    struct aws_byte_buf ciphertext_decrypted;
    rc = aws_kms_generate_data_key_blocking(
        client, app_ctx->genKeyId, app_ctx->genKeySpec, &plaintext, &ciphertext_decrypted);

    // struct aws_nitro_enclaves_kms_client *client,
    // const struct aws_string *key_id,
    // enum aws_key_spec key_spec,
    // struct aws_byte_buf *plaintext,
    // struct aws_byte_buf *ciphertext_blob
    // /* TODO: err_reason */) {
	fprintf(stdout, "%s", (const char *)plaintext.buffer);


    aws_byte_buf_clean_up(&plaintext);
    fail_on(rc != AWS_OP_SUCCESS, "Could not decrypt ciphertext");

    /* Encode ciphertext into base64 for printing out the result. */
    size_t output_len;
    struct aws_byte_cursor ciphertext_decrypted_cursor = aws_byte_cursor_from_buf(&ciphertext_decrypted);
    aws_base64_compute_encoded_len(ciphertext_decrypted.len, &output_len);
    rc = aws_byte_buf_init(output, app_ctx->allocator, output_len + 1);
    fail_on(rc != AWS_OP_SUCCESS, "Memory allocation error");
    rc = aws_base64_encode(&ciphertext_decrypted_cursor, output);
    fail_on(rc != AWS_OP_SUCCESS, "Base64 encoding error");
    aws_byte_buf_append_null_terminator(output);

    aws_nitro_enclaves_kms_client_destroy(client);
    aws_credentials_release(credentials);
    return AWS_OP_SUCCESS;
}

static int Command(struct app_ctx *app_ctx, struct aws_byte_buf *output) {
    ssize_t rc = 0;

    fprintf(stdout, "app_ctx->reqCommand : %d", app_ctx->reqCommand);

    switch(app_ctx->reqCommand){
        case DECRYPT:
            rc = decrypt(&app_ctx, &output);
            break;

        case GEN_RANDOM:
            rc = generateRandom(&app_ctx, &output);
            break;

        case GEN_DATA_KEY:
            rc = generateDataKey(&app_ctx, &output);
            break;

        default:
            fprintf(stderr, "Not Supported Command\n");
            exit(1);
    }

    return rc;
}

int main(int argc, char **argv) {
    struct app_ctx app_ctx;
    struct aws_byte_buf output;
    int rc;

    fprintf(stdout, "\n kmstool_enclave_cli main 00 \n");

    /* Initialize the SDK */
    aws_nitro_enclaves_library_init(NULL);

    fprintf(stdout, "\n kmstool_enclave_cli main 01 \n");

    /* Initialize the entropy pool: this is relevant for TLS */
    AWS_ASSERT(aws_nitro_enclaves_library_seed_entropy(1024) == AWS_OP_SUCCESS);

    fprintf(stdout, "\n kmstool_enclave_cli main 02 \n");

    /* Parse the commandline */
    app_ctx.allocator = aws_nitro_enclaves_get_allocator();

    fprintf(stdout, "\n kmstool_enclave_cli main 03 \n");

    s_parse_options(argc, argv, &app_ctx);

    fprintf(stdout, "\n kmstool_enclave_cli main 04 \n");


    /* Optional: Enable logging for aws-c-* libraries */
    struct aws_logger err_logger;
    struct aws_logger_standard_options options = {
        .file = stderr,
        .level = AWS_LL_INFO,
        .filename = NULL,
    };

    fprintf(stdout, "\n kmstool_enclave_cli main 05 \n");

    aws_logger_init_standard(&err_logger, app_ctx.allocator, &options);
    fprintf(stdout, "\n kmstool_enclave_cli main 06 \n");
    aws_logger_set(&err_logger);
    fprintf(stdout, "\n kmstool_enclave_cli main 07 \n");

    rc = Command(&app_ctx, &output);

    if (rc != AWS_OP_SUCCESS) {
        fprintf(stderr, "Could not decrypt\n");
        exit(1);
    }

    /* Print the base64-encoded plaintext to stdout */
    fprintf(stdout, "%s", (const char *)output.buffer);

    aws_byte_buf_clean_up(&output);
    aws_nitro_enclaves_library_clean_up();

    return 0;
}
