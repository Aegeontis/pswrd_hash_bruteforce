import 'dart:convert';
import 'dart:io';
import 'dart:isolate';
import 'dart:math';

import 'package:crypto/crypto.dart';

final chars = 'abcdefghijklmnopqrstuvwxyz'
        'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
        '0123456789'
        '"\',;.?!@#\$%^&*(){}\\~-_<>|§=`´°+*'
    .split('');

void main() async {
  stdout.write("Enter sha-1 hash of the password: ");
  String? passwordHash = stdin.readLineSync();
  if (passwordHash?.isEmpty ?? true) {
    print("No input provided.");
    exit(1);
  }

  stdout.write("Enter known part of the password: ");
  String? passwordKnown = stdin.readLineSync();
  if (passwordKnown?.isEmpty ?? true) {
    print("No input provided.");
    exit(1);
  }

  stdout.write("Enter amount of unknown chars at the end of the password: ");
  String? unknownCharsAmountString = stdin.readLineSync();
  if (int.tryParse(unknownCharsAmountString!) == null ||
      (unknownCharsAmountString.isEmpty)) {
    print("No/invalid input provided.");
    exit(1);
  }

  // Prep for the isolates
  final unknownCharsAmount = int.parse(unknownCharsAmountString);
  final totalCombinations = pow(chars.length, unknownCharsAmount).toInt();
  final numIsolates = Platform.numberOfProcessors;
  final receivePort = ReceivePort();
  final isolates = <Isolate>[];
  final chunkSize = (totalCombinations / numIsolates).ceil();
  final progress = List.filled(numIsolates, 0);
  final startTime = DateTime.now();

  // Start the isolates
  print("Starting with $numIsolates threads...");
  for (int i = 0; i < numIsolates; i++) {
    isolates.add(await Isolate.spawn(_bruteForce, [
      receivePort.sendPort,
      passwordHash!,
      passwordKnown!,
      unknownCharsAmount,
      i * chunkSize, // start
      min(i * chunkSize + chunkSize, totalCombinations), // end
      i
    ]));
  }

  // Track progress
  receivePort.listen((message) {
    // Terminate all isolates as soon as a match is found
    if (message is String) {
      print("\nMatch found: $message");
      for (final isolate in isolates) {
        isolate.kill(priority: Isolate.immediate);
      }
      exit(0);
    }

    // Store new progress
    progress[message["id"] as int] = message["completed"] as int;

    // recalculate total progress
    final completedTotal = progress.reduce((a, b) => a + b);
    final progressPercent = completedTotal / totalCombinations * 100;
    final elapsedTime = DateTime.now().difference(startTime).inSeconds;

    String timeRemainingText;
    // Don't try calculating time before at least one combination has been checked
    if (completedTotal > 0) {
      final estimatedTotalTime =
          (elapsedTime / (completedTotal / totalCombinations)).toInt();
      final remainingTime = max(estimatedTotalTime - elapsedTime, 0);

      final remainingHours = remainingTime ~/ 3600;
      final remainingMinutes = remainingTime ~/ 60;
      final remainingSeconds = remainingTime % 60;
      timeRemainingText = " | Time Remaining: "
          "${remainingHours != 0 ? "${remainingHours}h " : ""}"
          "${remainingMinutes != 0 ? "${remainingMinutes}m" : ""} "
          "${remainingSeconds}s";
    } else {
      timeRemainingText = " | Time Remaining: Calculating...";
    }

    // Replace the previous line
    stdout.write(
        "\rProgress: ${progressPercent.toStringAsFixed(2)}%$timeRemainingText");
  });
}

void _bruteForce(List args) {
  final sendPort = args[0] as SendPort;
  final passwordHash = args[1] as String;
  final passwordKnown = args[2] as String;
  final unknownCharsAmount = args[3] as int;
  final start = args[4] as int;
  final end = args[5] as int;
  final id = args[6] as int;

  for (int i = start; i < end; i++) {
    String combination = "";
    int temp = i;

    for (int j = 0; j < unknownCharsAmount; j++) {
      combination = chars[temp % chars.length] + combination;
      temp ~/= chars.length;
    }

    String testString = passwordKnown + combination;
    String hash = sha1.convert(utf8.encode(testString)).toString();

    if (hash == passwordHash) {
      sendPort.send(testString);
      return;
    }

    // Update progress periodically
    if ((i - start) % 1000 == 0) {
      sendPort.send({"id": id, "completed": i - start});
    }
  }

  // Send final progress
  sendPort.send({"id": id, "completed": end - start});
}
