import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';

import 'flutter_appauth_platform_interface.dart';

/// An implementation of [FlutterAppauthPlatform] that uses method channels.
class MethodChannelFlutterAppauth extends FlutterAppauthPlatform {
  /// The method channel used to interact with the native platform.
  @visibleForTesting
  final MethodChannel methodChannel = const MethodChannel('flutter_appauth');

  @override
  Future<String?> getPlatformVersion() async {
    final String? version = await methodChannel.invokeMethod<String>('getPlatformVersion');
    return version;
  }
}
