import 'dart:async';
import 'dart:io';

import 'package:shelf/shelf.dart';
import 'package:shelf/shelf_io.dart' as shelf_io;
import 'package:shelf_router/shelf_router.dart' as shelf_router;
import 'package:shelf_static/shelf_static.dart' as shelf_static;

import 'package:accom_validation_server/scripts_runner.dart';

Future main() async {
  // If the "PORT" environment variable is set, listen to it. Otherwise, 8080.
  // https://cloud.google.com/run/docs/reference/container-contract#port
  final port = int.parse(Platform.environment['PORT'] ?? '8080');

  // See https://pub.dev/documentation/shelf/latest/shelf/Cascade-class.html
  final cascade = Cascade()
      // First, serve files from the 'public' directory
      .add(_staticHandler)
      // If a corresponding file is not found, send requests to a `Router`
      .add(_router);

  // See https://pub.dev/documentation/shelf/latest/shelf_io/serve.html
  final server = await shelf_io.serve(
    // See https://pub.dev/documentation/shelf/latest/shelf/logRequests.html
    logRequests()
        // See https://pub.dev/documentation/shelf/latest/shelf/MiddlewareExtensions/addHandler.html
        .addHandler(cascade.handler),
    InternetAddress.anyIPv4, // Allows external connections
    port,
  );

  print('Serving at http://${server.address.host}:${server.port}');
}

// Serve files from the file system.
final _staticHandler =
    shelf_static.createStaticHandler('public', defaultDocument: 'index.html');

// Router instance to handler requests.
final _router = shelf_router.Router()
  ..post('/accomplish/<accomID|[a-zA-Z0-9-]+/[a-zA-Z0-9-]+>',
      _nocacheMiddleware.addHandler(_accomplishmentHandler))
  ..get('/helloworld', _helloWorldHandler);

Response _helloWorldHandler(Request request) => Response.ok('Hello, World!');

final _nocacheMiddleware = createMiddleware(
    responseHandler: (Response r) =>
        r.change(headers: {'Cache-Control': 'private, max-age: 0'}));

FutureOr<Response> _accomplishmentHandler(Request request) async {
  final accomID = request.params['accomID'];
  if (accomID != null) {
    return runScript(accomID, await request.readAsString());
  }
  return Response.notFound('');
}

// Response _sumHandler(request, String a, String b) {
//   final aNum = int.parse(a);
//   final bNum = int.parse(b);
//   return Response.ok(
//     const JsonEncoder.withIndent(' ')
//         .convert({'a': aNum, 'b': bNum, 'sum': aNum + bNum}),
//     headers: {
//       'content-type': 'application/json',
//       'Cache-Control': 'public, max-age=604800',
//     },
//   );
// }
