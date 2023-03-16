// In order to *not* need this ignore, consider extracting the "web" version
// of your plugin as a separate package, instead of inlining it in the same
// package as the core of your plugin.
// ignore: avoid_web_libraries_in_flutter


import 'dart:async';
import 'dart:convert';
import 'dart:core';
import 'dart:html' as html;
import 'dart:math';
import 'dart:typed_data';

import 'package:flutter_appauth_platform_interface/flutter_appauth_platform_interface.dart';
import 'package:flutter_web_plugins/flutter_web_plugins.dart';
import 'package:http/http.dart' as http;
import 'package:pointycastle/digests/sha256.dart';

import 'flutter_appauth.dart';
import 'flutter_appauth_platform_interface.dart';

/// A web implementation of the FlutterAppauthPlatform of the FlutterAppauth plugin.
class FlutterAppauthWeb extends FlutterAppauthPlatform {
  /// Constructs a FlutterAppauthWeb
  FlutterAppauthWeb();

  static void registerWith(Registrar registrar) {
    FlutterAppauthPlatform.instance = FlutterAppauthWeb();
  }

  /// Returns a [String] containing the version of the platform.
  @override
  Future<String?> getPlatformVersion() async {
    final String version = html.window.navigator.userAgent;
    return version;
  }

  static const String _charset = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~';
  static const String _discoveryErrorMessageFormat = 'Error retrieving discovery document: [error: discovery_failed, description: %2]';
  static const String _tokenErrorMessageFormat = 'Failed to get token: [error: token_failed, description: %2]';
  static const String _authorizeErrorMessageFormat = 'Failed to authorize: [error: %1, description: %2]';

  static const String _authorizeAndExchangeCodeErrorCode = 'authorize_and_exchange_code_failed';
  static const String _authorizeErrorCode = 'authorize_failed';

  static const String _codeVerifierStorage = 'auth_code_verifier';
  static const String _authorizeDestinationUrl = 'auth_destination_url';
  static const String _authResponseInfo = 'auth_info';

  Future<AuthorizationTokenResponse?> authorizeAndExchangeCode(AuthorizationTokenRequest request) async {
    final String? authUrl = html.window.sessionStorage[_authorizeDestinationUrl];

    if (authUrl != null || authUrl != null && authUrl.isNotEmpty) {
      return null;
    }

    final AuthorizationResponse? authResult = await authorize(
      AuthorizationRequest(
        request.clientId,
        request.redirectUrl,
        loginHint: request.loginHint,
        scopes: request.scopes,
        serviceConfiguration: request.serviceConfiguration,
        additionalParameters: request.additionalParameters,
        allowInsecureConnections: request.allowInsecureConnections!,
        discoveryUrl: request.discoveryUrl,
        issuer: request.issuer,
        preferEphemeralSession: request.preferEphemeralSession!,
        promptValues: request.promptValues,
      ),
    );

    if (authResult == null) {
      return null;
    }

    final TokenResponse tokenResponse = await requestToken(
      TokenRequest(request.clientId, request.redirectUrl,
          clientSecret: request.clientSecret,
          serviceConfiguration: request.serviceConfiguration,
          allowInsecureConnections: request.allowInsecureConnections!,
          authorizationCode: authResult.authorizationCode,
          codeVerifier: authResult.codeVerifier,
          discoveryUrl: request.discoveryUrl,
          grantType: 'authorization_code',
          issuer: request.issuer),
    );

    return AuthorizationTokenResponse(
      tokenResponse.accessToken,
      tokenResponse.refreshToken,
      tokenResponse.accessTokenExpirationDateTime,
      tokenResponse.idToken,
      tokenResponse.tokenType,
      tokenResponse.scopes,
      authResult.authorizationAdditionalParameters,
      tokenResponse.tokenAdditionalParameters,
    );
  }

  Future<AuthorizationResponse?> authorize(AuthorizationRequest request) async {
    String? codeVerifier;

    // check if we already have login-callback data
    final String? authUrl = html.window.sessionStorage[_authResponseInfo];
    if (authUrl != null && authUrl.isNotEmpty) {
      html.window.sessionStorage.remove(_authResponseInfo);

      codeVerifier = html.window.sessionStorage[_codeVerifierStorage];
      if (codeVerifier == null || codeVerifier.isEmpty) {
        return null;
      }
      html.window.sessionStorage.remove(_codeVerifierStorage);

      return processLoginResult(authUrl, codeVerifier);
    }

    final AuthorizationServiceConfiguration serviceConfiguration = await getConfiguration(request.serviceConfiguration, request.discoveryUrl, request.issuer);

    request.serviceConfiguration = serviceConfiguration; //Fill in the values from the discovery doc if needed for future calls.
    codeVerifier = List.generate(128, (int i) => _charset[Random.secure().nextInt(_charset.length)]).join();

    final String codeChallenge = base64Url.encode(SHA256Digest().process(Uint8List.fromList(codeVerifier.codeUnits))).replaceAll('=', '');

    String responseType = 'code';

    String authUri =
        "${serviceConfiguration.authorizationEndpoint}?client_id=${request.clientId}&redirect_uri=${Uri.encodeQueryComponent(request.redirectUrl)}&response_type=$responseType&scope=${Uri.encodeQueryComponent(request.scopes!.join(' '))}&code_challenge_method=S256&code_challenge=$codeChallenge";

    if (request.loginHint != null) {
      authUri += '&login_hint=${Uri.encodeQueryComponent(request.loginHint!)}';
    }

    if (request.promptValues != null) {
      for (String element in request.promptValues!) {
        authUri += '&prompt=$element';
      }
    }
    if (request.additionalParameters != null) {
      request.additionalParameters!.forEach((String key, String value) => authUri += '&$key=$value');
    }

    String loginResult;
    try {
      if (request.promptValues != null && request.promptValues!.contains('none')) {
        //Do this in an iframe instead of a popup because this is a silent renew
        loginResult = await openIframe(authUri, 'auth');
      } else {
        html.window.sessionStorage[_authorizeDestinationUrl] = html.window.location.href;
        html.window.sessionStorage[_codeVerifierStorage] = codeVerifier;
        html.window.location.assign(authUri);
        return null;
        // loginResult = await openPopUp(authUri, 'auth', 640, 600, true);
      }
    } on StateError catch (err) {
      throw StateError(_authorizeErrorMessageFormat.replaceAll('%1', _authorizeAndExchangeCodeErrorCode).replaceAll('%2', err.message));
    }

    return processLoginResult(loginResult, codeVerifier);
  }

  @override
  Future<TokenResponse> token(TokenRequest request) {
    return requestToken(request);
  }

  @override
  Future<EndSessionResponse?> endSession(EndSessionRequest request) async {
    final AuthorizationServiceConfiguration serviceConfiguration = await getConfiguration(request.serviceConfiguration, request.discoveryUrl, request.issuer);
    String uri = '${serviceConfiguration.endSessionEndpoint}?id_token_hint=${request.idTokenHint}';

    if (request.idTokenHint != null && request.postLogoutRedirectUrl != null) {
      uri += '&post_logout_redirect_uri=${Uri.encodeQueryComponent(request.postLogoutRedirectUrl!)}';
    }

    if (request.postLogoutRedirectUrl != null && request.state != null) {
      uri += '&state=${request.state}';
    }

    // lets redirect to the endsession uri
    html.window.location.assign(uri);

    return EndSessionResponse(null);
  }

  Future<TokenResponse> requestToken(TokenRequest request) async {
    final AuthorizationServiceConfiguration serviceConfiguration = await getConfiguration(request.serviceConfiguration, request.discoveryUrl, request.issuer);

    request.serviceConfiguration = serviceConfiguration; //Fill in the values from the discovery doc if needed for future calls

    Map<String, String?> body = {'client_id': request.clientId, 'grant_type': request.grantType, 'redirect_uri': request.redirectUrl};

    if (request.clientSecret != null) {
      body['client_secret'] = request.clientSecret;
    }

    if (request.authorizationCode != null) {
      body['code'] = request.authorizationCode;
    }
    if (request.codeVerifier != null) {
      body['code_verifier'] = request.codeVerifier;
    }
    if (request.refreshToken != null) {
      body['refresh_token'] = request.refreshToken;
    }
    if (request.scopes != null && request.scopes!.isNotEmpty) {
      body['scopes'] = request.scopes!.join(' ');
    }

    if (request.additionalParameters != null) {
      body.addAll(request.additionalParameters!);
    }

    final http.Response response = await http.post(Uri.parse(serviceConfiguration.tokenEndpoint), body: body);

    final Map<String, dynamic> jsonResponse = jsonDecode(response.body);

    if (response.statusCode != 200) {
      print(jsonResponse['error'].toString());
      throw ArgumentError(_tokenErrorMessageFormat.replaceAll('%2', jsonResponse['error']?.toString() ?? response.reasonPhrase ?? 'Unknown Error'));
    }
    List<String>? scopes = jsonResponse['scope'] is String == true
        ? ((jsonResponse['scope'].split(' ') as List?)?.cast<String>())
        : (jsonResponse['scope'] as List?)?.cast<String>();
    return TokenResponse(
      jsonResponse['access_token'].toString(),
      jsonResponse['refresh_token'] == null ? null : jsonResponse['refresh_token'].toString(),
      DateTime.now().add(Duration(seconds: jsonResponse['expires_in'])),
      jsonResponse['id_token'].toString(),
      jsonResponse['token_type'].toString(),
      scopes,
      jsonResponse,
    );
  }

  //returns null if full login is required
  AuthorizationResponse processLoginResult(String loginResult, String codeVerifier) {
    Uri resultUri = Uri.parse(loginResult.toString());

    final String? error = resultUri.queryParameters['error'];

    if (error != null && error.isNotEmpty) {
      throw ArgumentError(_authorizeErrorMessageFormat.replaceAll('%1', _authorizeErrorCode).replaceAll('%2', error));
    }

    String? authCode = resultUri.queryParameters['code'];
    if (authCode == null || authCode.isEmpty) {
      throw ArgumentError(_authorizeErrorMessageFormat.replaceAll('%1', _authorizeErrorCode).replaceAll('%2', 'Login request returned no code'));
    }

    return AuthorizationResponse(
      authorizationCode: authCode,
      codeVerifier: codeVerifier,
      authorizationAdditionalParameters: resultUri.queryParameters,
    );
  }

  //to-do Cache this based on the url
  Future<AuthorizationServiceConfiguration> getConfiguration(
      AuthorizationServiceConfiguration? serviceConfiguration, String? discoveryUrl, String? issuer) async {
    if ((discoveryUrl == null || discoveryUrl == '') && (issuer == null || issuer == '') && serviceConfiguration == null) {
      throw ArgumentError('You must specify either a discoveryUrl, issuer, or serviceConfiguration');
    }

    if (serviceConfiguration != null) {
      return serviceConfiguration;
    }

    //Handle lookup here.
    if (discoveryUrl == null || discoveryUrl == '') {
      discoveryUrl = '$issuer/.well-known/openid-configuration';
    }

    
    final http.Response response = await http.get(Uri.parse(discoveryUrl));

    if (response.statusCode != 200) {
      throw UnsupportedError(_discoveryErrorMessageFormat.replaceAll('%2', response.reasonPhrase ?? 'Unknown Error'));
    }

    final dynamic jsonResponse = jsonDecode(response.body);
    return AuthorizationServiceConfiguration(
      authorizationEndpoint: jsonResponse['authorization_endpoint'].toString(),
      tokenEndpoint: jsonResponse['token_endpoint'].toString(),
      endSessionEndpoint: jsonResponse['end_session_endpoint'].toString(),
    );
  }

  Future<String> openPopUp(String url, String name, int width, int height, bool center, {String? additionalOptions}) async {
    String options = 'width=$width,height=$height,toolbar=no,location=no,directories=no,status=no,menubar=no,copyhistory=no';
    if (center) {
      final double top = (html.window.outerHeight - height) / 2 + (html.window.screen?.available.top ?? 0);
      final double left = (html.window.outerWidth - width) / 2 + (html.window.screen?.available.left ?? 0);

      options += 'top=$top,left=$left';
    }

    if (additionalOptions != null && additionalOptions != '') {
      options += ',$additionalOptions';
    }

    final html.WindowBase child = html.window.open(url, name, options);
    final Completer<String> c = Completer<String>();

    html.window.onMessage.first.then((html.MessageEvent event) {
      final String url = event.data.toString();
      print(url);
      c.complete(url);
      child.close();
    });

    //This handles the user closing the window without a response
    while (!c.isCompleted) {
      await Future.delayed(const Duration(milliseconds: 500));
      if ((child.closed ?? false) && !c.isCompleted) {
        c.completeError(StateError('User Closed'));
      }

      if (c.isCompleted) {
        break;
      }
    }

    return c.future;
  }

  Future<String> openIframe(String url, String name) async {
    final html.IFrameElement child = html.IFrameElement();
    child.name = name;
    child.src = url;
    child.height = '10';
    child.width = '10';
    child.style.border = 'none';
    child.style.display = 'none';

    html.querySelector('body')?.children.add(child);

    final Completer<String> c = Completer<String>();

    html.window.onMessage.first.then((html.MessageEvent event) {
      final String url = event.data.toString();
      print(url);
      c.complete(url);
      html.querySelector('body')?.children.remove(child);
    });

    return c.future;
  }
}
