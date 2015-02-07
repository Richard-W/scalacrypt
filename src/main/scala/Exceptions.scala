/* Copyright 2014, 2015 Richard Wiedenhöft <richard@wiedenhoeft.xyz>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package xyz.wiedenhoeft.scalacrypt

/* Exceptions MUST never be thrown in this project. They must be
 * returned inside a failure.
 */

/** Occurs when invalid padding is encountered. */
class BadPaddingException(message: String) extends Exception("Bad padding: " + message)

/** Occurs when a block of illegal size is given to a block cipher. */
class IllegalBlockSizeException(message: String) extends Exception("Illegal block size: " + message)

/** Occurs when ciphertexts are invalid. */
class InvalidCiphertextException(message: String) extends Exception("Invalid ciphertext: " + message)

/** Occurs when during decryption problems are encountered. */
class DecryptionException(message: String) extends Exception("Decryption: " + message)

/** Occurs when during encryption problems are encountered. */
class EncryptionException(message: String) extends Exception("Encryption: " + message)

/** Occurs when problems are encountered during key creation. */
class KeyException(message: String) extends Exception("Key creation: " + message)

/** Occurs when an iteratee behaves erratically. */
class IterateeException(message: String) extends Exception("Iteratee: " + message)

/** Occurs when a keyed hash fails. */
class KeyedHashException(message: String) extends Exception("KeyedHash: " + message)

/** Occurs when something is wrong with the given parameters. */
class ParameterException(val symbol: Symbol, message: String) extends Exception("Parameters: " + message)
