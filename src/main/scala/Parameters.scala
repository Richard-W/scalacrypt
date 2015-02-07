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

import scala.util.{ Try, Success, Failure }

object Parameters {
  import scala.reflect.ClassTag

  def apply(params: (Symbol, Any)*): Parameters = params.toMap

  def checkParam[A : ClassTag](params: Parameters, symbol: Symbol): Try[A] = {
    params.get(symbol) match {
      case Some(maybeParam) ⇒
      maybeParam match {
        case param: A ⇒ Success(param)
        case _ ⇒ Failure(new ParameterException(symbol, "Symbol " + symbol.toString + " has unexpected type."))
      }
      case _ ⇒ Failure(new ParameterException(symbol, "Parameter " + symbol.toString + " not found."))
    }
  }
}

