import 'package:plugin_platform_interface/plugin_platform_interface.dart';

import 'flutter_appauth_method_channel.dart';

abstract class FlutterAppauthPlatform extends PlatformInterface {
  /// Constructs a FlutterAppauthPlatform.
  FlutterAppauthPlatform() : super(token: _token);

  static final Object _token = Object();

  static FlutterAppauthPlatform _instance = MethodChannelFlutterAppauth();

  /// The default instance of [FlutterAppauthPlatform] to use.
  ///
  /// Defaults to [MethodChannelFlutterAppauth].
  static FlutterAppauthPlatform get instance => _instance;

  /// Platform-specific implementations should set this with their own
  /// platform-specific class that extends [FlutterAppauthPlatform] when
  /// they register themselves.
  static set instance(FlutterAppauthPlatform instance) {
    PlatformInterface.verifyToken(instance, _token);
    _instance = instance;
  }

  Future<String?> getPlatformVersion() {
    throw UnimplementedError('platformVersion() has not been implemented.');
  }
}
