part of 'types.dart';

/// A failure reported by a bundled cryptographic implementation.
final class KpqCException implements Exception {
  /// Creates an exception for [operation] and the native [status] code.
  const KpqCException(this.operation, this.status);

  /// The operation that failed.
  final String operation;

  /// The status returned by the native implementation.
  final int status;

  @override
  String toString() => 'KpqCException: $operation failed with status $status';
}
