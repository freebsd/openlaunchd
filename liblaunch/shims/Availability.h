/*
 * Copyright (c) 2013 R. Tyler Croy
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*'
 * Availability is Apple OS functionality for tagging function prototypes with
 * the version of OS in which they became available, or in which version they
 * will be deprecated.
 */

#ifndef __AVAILABILITY_H__
#define __AVAILABILITY_H__

#define __OSX_AVAILABLE_STARTING(x, y) __attribute__((visibility("default")))

#endif
