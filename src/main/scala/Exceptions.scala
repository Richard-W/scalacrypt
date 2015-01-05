/* Copyright 2014 Richard Wiedenhoeft <richard@wiedenhoeft.xyz>
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

/** Occurs when ciphertexts are invalid. */
class InvalidCiphertextException(message: String) extends Exception("Invalid ciphertext: " + message)

/** Occurs when during decryption problems are encountered. */
class DecryptionException(message: String) extends Exception("Decryption: " + message)

/** Occurs when problems are encountered during key creation. */
class KeyException(message: String) extends Exception("Key creation: " + message)
