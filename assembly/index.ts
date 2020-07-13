export * from "@solo-io/proxy-runtime/proxy";
import {
  Context,
  ContextHelper,
  FilterHeadersStatusValues,
  registerRootContext,
  RootContext,
  RootContextHelper,
  stream_context,
} from "@solo-io/proxy-runtime";

import { GrpcStatusValues, send_local_response } from "@solo-io/proxy-runtime/runtime";

import * as md5 from "../node_modules/as-crypto/lib/md5";

class SecureLinkRoot extends RootContext {
  configuration: string;

  /* This function is called when Envoy loads the WASM module if the configuration
  has not already been loaded into the VM running the module.

  This method can only be called in the root context.
  https://github.com/proxy-wasm/proxy-wasm-cpp-sdk/blob/master/docs/wasm_filter.md#onconfigure
  */
  onConfigure(): bool {
    let conf_buffer = super.getConfiguration();
    let result = String.UTF8.decode(conf_buffer);
    this.configuration = result;

    // Signal to the Wasm VM that the filter has properly initialized
    return true;
  }

  // Called at the beginning of filter chain iteration.
  // Indicates creation of the new stream context.
  createContext(): Context {
    return ContextHelper.wrap(new SecureLink(this));
  }
}

class SecureLink extends Context {
  root_context: SecureLinkRoot;

  // List of protected URL paths
  private _protected_paths: Array<string>;

  // Secure Link secret
  private _secure_link_secret: string;

  constructor(root_context:SecureLinkRoot){
    super();
    // Associates the parent root context with this stream context
    this.root_context = root_context;

    // Parse defined configuration
    this.parseConfiguration();
  }

  // Converts a string to an array
  private str2array(str: string): Uint8Array {
    let list = new Uint8Array(str.length);
    for (let i = 0; i < str.length; i++) {
      list[i] = str.charCodeAt(i)
    }
    return list;
  }

  // Returns a hexadecimal representation of the MD5 hashed string
  private md532(str: string): string {
    return md5.hex32(this.str2array(str));
  }

  // Parse and load defined configuration
  private parseConfiguration(): void {
    const root_context = this.root_context;

    // Initialize default configuration values
    this._secure_link_secret = "";
    this._protected_paths = new Array<string>(1);

    // Parse config if defined
    if (root_context.configuration != "") {
      // Parse configuration values
      // Format is: <secret>|<paths>
      const configuration = root_context.configuration.split("|");

      if (configuration.length == 2) {
        // Shared secret used for hashing values
        this._secure_link_secret = configuration[0];

        // Protected paths
        this._protected_paths = configuration[1].split(',')
      }
    }
  }

  /*
  Parses request path and returns map containing various components
  The full URI of a requested link looks as follows:

  /prefix/hash/link

  where hash is a hexadecimal representation of the MD5 hash computed for
  the concatenation of the link and secret word, and prefix is an arbitrary
  string without slashes.

  Ref: http://nginx.org/en/docs/http/ngx_http_secure_link_module.html
  */
  private parseRequestPath(path: string): Map<string, string> {

    let path_obj = new Map<string, string>();

    // Check if URL matches one of our secured paths
    for (let index = 0; index < this._protected_paths.length; index++) {
      const element = this._protected_paths[index];
      if (isString(element) && path.startsWith(element)) {
        path_obj.set("prefix", element);
        break;
      }
    }

    if (!path_obj.has("prefix")) {
      return path_obj;
    }

    // Parse out the remaining parts of the URL
    const prefix_str_length = path_obj.get("prefix").length;
    const path_remainder = path.slice(prefix_str_length);

    // Stop processing filter if '/' is not found
    // Indicates URI does not contain required fragments
    const hash_link_delimiter = path_remainder.indexOf('/')
    if (hash_link_delimiter !=  -1) {
      path_obj.set("hash", path_remainder.slice(0, hash_link_delimiter));

      const link = path_remainder.slice(hash_link_delimiter + 1);
      if (link.length > 0) {
        path_obj.set("link", link);
      }
    }

    return path_obj;
  }

  // Reject request with 401, and stop filter chain processing
  private rejectRequest(): FilterHeadersStatusValues {
    // Allocate a buffer for the body to return in the request
    const buffer = String.UTF8.encode('Unauthorized');

    /*
    Sends HTTP response without forwarding request to the upstream.

    https://github.com/proxy-wasm/spec/tree/master/abi-versions/vNEXT#proxy_send_http_response
    */
    send_local_response(
      // Response code
      401,
      // Response code details
      "Unauthorized",
      // Body
      buffer,
      // Additional headers
      [],
      // gRPC status
      GrpcStatusValues.PermissionDenied
    );

    // Do not iterate to any of the remaining filters in the chain.
    return FilterHeadersStatusValues.StopIteration;
  }

  /*
  Called when headers are decoded.

  Returns FilterHeadersStatus to determine how filter chain iteration proceeds.

  https://github.com/proxy-wasm/proxy-wasm-cpp-sdk/blob/master/docs/wasm_filter.md#onrequestheaders
  */
  onRequestHeaders(a: i32): FilterHeadersStatusValues {
    const root_context = this.root_context;

    // If configuration is blank, stop execution and continue filter chain
     if (this._secure_link_secret == "" || this._protected_paths.length == 0) {
      return FilterHeadersStatusValues.Continue;
    }

    // Get the requested URL path
    const url_path = stream_context.headers.request.get(":path") || "";
    const parsed_path = this.parseRequestPath(url_path);

    // If the URL does not match one of our protected paths
    if (!parsed_path.has("prefix")) {
      // Stop processing and continue filter chain iteration
      return FilterHeadersStatusValues.Continue;
    }

    // Reject request if path does not contain a hash or link
    if (!parsed_path.has("hash") || !parsed_path.has("link")) {
      return this.rejectRequest();
    }

    const request_hash = parsed_path.get("hash");

    // Generate our own hash from the shared secret
    const secret_hash = this.md532(parsed_path.get("link") + this._secure_link_secret);

    // Compare provided hash to our generated secret hash
    if (request_hash == secret_hash) {

      // Remove path header from request
      stream_context.headers.request.remove(":path");

      // Modify request request path to remove hash
      const modified_path = url_path.replace(request_hash + "/", "");

      // Re-add modified path header to request
      stream_context.headers.request.add(":path", modified_path);

      // Stop processing request and continue filter chain iteration, effectively
      // forwarding request to upstream
      return FilterHeadersStatusValues.Continue;
    }

    // Otherwise, default reject the request
    return this.rejectRequest();
  }
}

registerRootContext(
  () => { return RootContextHelper.wrap(new SecureLinkRoot()); },

  // root_id: The name of our filter
  // This name is referenced in the Envoy configuration.
  //
  // https://github.com/envoyproxy/envoy-wasm/blob/097b7f2/api/envoy/config/wasm/v2/wasm.proto#L42-L45
  "secure_link"
);
