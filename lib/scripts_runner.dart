import 'dart:convert';
import 'dart:io';

import 'package:encrypt/encrypt.dart';
import 'package:path/path.dart' as path;
import 'package:pointycastle/asymmetric/api.dart';
import 'package:process/process.dart';
import 'package:shelf/shelf.dart';

final privateKey =
    RSAKeyParser().parse(Platform.environment['ACCOMPLISHMENTS_PRIVKEY'] ?? '')
        as RSAPrivateKey;

Signer signer = Signer(
  RSASigner(
    RSASignDigest.SHA256,
    privateKey: privateKey,
  ),
);

final procman = LocalProcessManager();

Future<Response> runScript(String accomID, String data) async {
  final scriptpath = await getScript(accomID);
  Map<String, dynamic> trophy = jsonDecode(data);
  List<String> extraInformationNames = trophy['needs-information'].split(',');
  Map<String, String> extraInformationData = {};
  for (var item in extraInformationNames) {
    if (trophy.containsKey(item) &&
        trophy[item] != null &&
        trophy[item] != "") {
      extraInformationData[item] = trophy[item];
    }
  }
  if (scriptpath == null) {
    return Response.notFound('no script');
  } else if (extraInformationData.isEmpty) {
    return Response.forbidden('');
  } else {
    final result =
        await procman.run([scriptpath, jsonEncode(extraInformationData)]);
    switch (result.exitCode) {
      case 0:
        final asc = signer.sign(data).base64;
        return Response.ok(asc);
      case 1:
        return Response.forbidden('');
      case 2:
        return Response.internalServerError();
      case 4:
        return Response.notFound('');
    }
    return Response.internalServerError();
  }
}

Future<String?> getScript(String accomID) async {
  final collection = accomID.split("/")[0];
  final accomfile = accomID.split("/")[1];
  final scriptname = "$accomfile.py";

  final scriptspath = path.join('accomplishments', 'scripts', collection);
  final scriptsDir = Directory(scriptspath);
  if (await scriptsDir.exists()) {
    await for (var f in scriptsDir.list(recursive: true)) {
      if ((await f.stat()).type == FileSystemEntityType.file) {
        if (path.basename(f.path) == scriptname) {
          print(f.absolute.path);
          return f.absolute.path;
        }
      }
    }
  }
  return null;
}
