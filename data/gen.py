"""
Copyright 2026 Faris Muhammad

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""

# Word list sourced from: https://github.com/dwyl/english-words (Unlicense)

import urllib.request
import re

url = "https://raw.githubusercontent.com/dwyl/english-words/master/words_alpha.txt"
text = urllib.request.urlopen(url).read().decode('utf-8')

clean_words = [w for w in text.splitlines() if re.match(r'^[a-z]+$', w)]

with open('dictionary.txt', 'w') as f:
    f.write('\n'.join(clean_words))
