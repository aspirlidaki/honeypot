# Python Notes — Personal Reference

---

## What is Python?

Python is a programming language. You write instructions in a `.py` file, run it, and the computer follows them top to bottom.

To run a file:
```
python cluster_attackers.py
```

---

## Variables

A variable is just a name you give to a value so you can use it later.

```python
name = "Anastasia"
age = 21
score = 9.5
```

You do not declare a type — Python figures it out on its own.

---

## Data Types

| Type | Example | What it is |
|------|---------|------------|
| `str` | `"hello"` | Text (always in quotes) |
| `int` | `42` | Whole number |
| `float` | `3.14` | Decimal number |
| `bool` | `True` / `False` | Yes or no |
| `list` | `[1, 2, 3]` | Ordered collection, can change |
| `tuple` | `(1, 2, 3)` | Ordered collection, cannot change |
| `set` | `{1, 2, 3}` | Unordered, no duplicates |
| `dict` | `{"a": 1}` | Key → value pairs |

---

## Lists

```python
fruits = ["apple", "banana", "cherry"]

fruits[0]        # "apple"  — indexing starts at 0
fruits[-1]       # "cherry" — negative index counts from the end
fruits[0:2]      # ["apple", "banana"] — a slice (from index 0 up to but not including 2)

fruits.append("mango")   # add to the end
fruits.remove("banana")  # remove by value
len(fruits)              # how many items
```

---

## Dictionaries

A dictionary maps a key to a value — like a real dictionary maps a word to its definition.

```python
person = {"name": "Anastasia", "age": 21}

person["name"]           # "Anastasia"
person["age"] = 22       # update a value
person["city"] = "Athens"  # add a new key

"name" in person         # True — check if a key exists
```

---

## Sets

A set holds unique values only. Adding the same thing twice has no effect.

```python
seen = {"apple", "banana", "apple"}
# seen is now {"apple", "banana"} — duplicate removed

seen.add("cherry")
"apple" in seen      # True — fast membership check
```

In the honeypot code, sets are used for `ip_to_pairs` so that if the same attacker retries the same password 100 times, it only gets counted once.

---

## If / Else

```python
x = 10

if x > 5:
    print("big")
elif x == 5:
    print("exactly five")
else:
    print("small")
```

Indentation (the spaces) is how Python knows what belongs inside the if-block. It is not optional.

---

## Loops

**For loop** — repeat for each item in a collection:

```python
for fruit in ["apple", "banana", "cherry"]:
    print(fruit)
```

**While loop** — repeat as long as a condition is true:

```python
count = 0
while count < 3:
    print(count)
    count += 1
```

**Range** — loop a set number of times:

```python
for i in range(5):     # 0, 1, 2, 3, 4
    print(i)
```

---

## Functions

A function is a reusable block of code. You define it once, call it many times.

```python
def greet(name):
    return "Hello, " + name

result = greet("Anastasia")
print(result)   # Hello, Anastasia
```

`def` = define a function  
`return` = send a value back to whoever called it  
If there is no `return`, the function gives back `None`.

---

## f-strings (formatted strings)

The cleanest way to put a variable inside a string:

```python
name = "Anastasia"
score = 9.5

print(f"Hello {name}, your score is {score:.1f}")
# Hello Anastasia, your score is 9.5
```

`:.1f` means "show one decimal place". You see this a lot in the honeypot code for printing IDF scores.

---

## Common Built-in Functions

| Function | What it does |
|----------|-------------|
| `print(x)` | Show something on screen |
| `len(x)` | Count items in a list, string, dict, etc. |
| `range(n)` | Numbers 0 to n-1 |
| `type(x)` | What type is x? |
| `int("42")` | Convert string to integer |
| `str(42)` | Convert integer to string |
| `sorted(x)` | Return a sorted copy of a list |
| `sum(x)` | Add up all numbers in a list |
| `max(x)` | Largest value |
| `min(x)` | Smallest value |

---

## Imports

Python has a huge standard library. You bring in what you need:

```python
import math
import csv
import collections
```

Then use it with a dot:

```python
math.log(100)     # natural log of 100
math.sqrt(9)      # 3.0
```

Some imports use an alias to save typing:

```python
import numpy as np
import matplotlib.pyplot as plt

np.array([1, 2, 3])    # instead of numpy.array(...)
plt.show()             # instead of matplotlib.pyplot.show()
```

---

## Collections Module

`defaultdict` — a dictionary that never throws a "key not found" error. Instead it creates a default value automatically.

```python
from collections import defaultdict

word_count = defaultdict(int)   # default value is 0
word_count["hello"] += 1        # works even though "hello" didn't exist yet
```

`Counter` — counts occurrences automatically:

```python
from collections import Counter

votes = Counter(["yes", "no", "yes", "yes", "no"])
votes.most_common(1)   # [("yes", 3)]
```

Both are used heavily in the honeypot code.

---

## Reading a CSV File

```python
import csv

with open("data.csv", newline="", encoding="utf-8") as fh:
    reader = csv.DictReader(fh)   # each row becomes a dictionary
    for row in reader:
        print(row["ip"], row["username"])
```

`DictReader` uses the first row (the header) as keys, so you access columns by name instead of position.

---

## Writing a CSV File

```python
import csv

with open("output.csv", "w", newline="", encoding="utf-8") as fh:
    writer = csv.writer(fh)
    writer.writerow(["name", "score"])    # header
    writer.writerow(["Anastasia", 9.5])   # data row
```

---

## Classes (Brief Overview)

A class is a blueprint for creating objects. Each object has its own data and behaviour.

```python
class Dog:
    def __init__(self, name):   # runs when you create a new Dog
        self.name = name

    def bark(self):
        return f"{self.name} says woof!"

my_dog = Dog("Rex")
print(my_dog.bark())    # Rex says woof!
```

`self` refers to the specific object. You always write it as the first argument in methods, but you never pass it manually — Python handles it.

---

## Errors You Will See Often

| Error | What it means |
|-------|--------------|
| `NameError` | You used a variable that does not exist |
| `TypeError` | Wrong type — e.g. adding a number to a string |
| `IndexError` | You asked for `list[5]` but the list only has 3 items |
| `KeyError` | You asked for a dict key that does not exist |
| `FileNotFoundError` | The file path is wrong |
| `IndentationError` | Your spacing is inconsistent |
| `ZeroDivisionError` | You divided by zero |

---

## Math in the Honeypot Code

**`math.log(x)`** — natural logarithm. Used for IDF.
The log function grows slowly, which is the point: it stops very rare pairs from dominating by an unrealistic amount.

```python
import math
math.log(4973 / 7)      # 6.563 — rare pair
math.log(4973 / 2791)   # 0.578 — common pair
```

**Cosine similarity** — measures how similar two lists of numbers are, regardless of their size. Output is between 0 (nothing in common) and 1 (identical). The honeypot uses this to compare credential sets between IPs.

---

## Tips

- Python is case-sensitive. `Name` and `name` are different variables.
- Strings use `"double"` or `'single'` quotes — both work, just be consistent.
- Comments start with `#` — Python ignores everything after it on that line.
- You can test small things quickly by typing `python` in the terminal and entering code line by line (interactive mode). Press Ctrl+D to exit.
- When something breaks, read the last line of the error first — it tells you what went wrong. Then look at the line number above it to find where.

---

## Mini Project — Student Course Clustering

A smaller version of the honeypot project. Same logic, friendlier data.

**The idea:**
You have a list of students and the courses each one is taking.
Students who take the same *rare* courses are probably in the same programme or study group.
Find those groups.

This mirrors the honeypot exactly:
- Students = attacker IPs
- Courses = credential pairs
- Rare shared course = meaningful connection

---

### Step 1 — Create your CSV file

Save this as `students.csv`:

```
student,course
Alice,Maths
Alice,Physics
Alice,CompSci
Bob,Maths
Bob,Physics
Bob,Chemistry
Carol,CompSci
Carol,Databases
Carol,Networking
Dave,Databases
Dave,Networking
Eve,Maths
Eve,Chemistry
```

---

### Step 2 — Load the data

```python
import csv
import collections
import math

def load_data(filepath):
    records = []
    with open(filepath, newline="", encoding="utf-8") as fh:
        reader = csv.DictReader(fh)
        for row in reader:
            records.append((row["student"].strip(), row["course"].strip()))
    return records
```

What to remember:
- `csv.DictReader` gives you each row as a dictionary — access columns by name
- `.strip()` removes accidental spaces around values
- You are building a list of tuples `(student, course)`

---

### Step 3 — Build mappings

```python
def build_mappings(records):
    course_to_students = collections.defaultdict(set)
    student_to_courses = collections.defaultdict(set)

    for student, course in records:
        course_to_students[course].add(student)
        student_to_courses[student].add(course)

    return course_to_students, student_to_courses
```

What to remember:
- `defaultdict(set)` creates an empty set automatically when a new key is first used — no KeyError
- You use a `set` (not a list) so that if a student appears twice with the same course, it is only counted once
- You build two mappings because you need to look things up in both directions

---

### Step 4 — Compute IDF (how rare is each course?)

```python
def compute_idf(course_to_students, total_students):
    idf = {}
    for course, student_set in course_to_students.items():
        df = len(student_set)
        idf[course] = math.log(total_students / df)
    return idf
```

What to remember:
- `math.log` is the natural logarithm — it grows slowly, which stops very popular courses from dominating
- A course taken by everyone has a low IDF (not useful)
- A course taken by very few people has a high IDF (very meaningful if two students share it)

---

### Step 5 — Score every pair of students

```python
def score_pairs(student_to_courses, idf):
    students = list(student_to_courses.keys())
    scores = {}

    for i in range(len(students)):
        for j in range(i + 1, len(students)):   # avoid comparing a student to themselves
            a = students[i]
            b = students[j]
            shared = student_to_courses[a] & student_to_courses[b]  # set intersection
            if shared:
                score = sum(idf[course] for course in shared)
                scores[(a, b)] = score

    return scores
```

What to remember:
- `range(i + 1, len(students))` means j is always ahead of i — each pair is only compared once
- `set_a & set_b` gives you the items that appear in both sets (intersection)
- `sum(... for ... in ...)` is a generator expression — a compact way to add up values from a loop

---

### Step 6 — Print the results

```python
def print_results(scores, threshold=1.0):
    print(f"Pairs with IDF score >= {threshold}:\n")
    for (a, b), score in sorted(scores.items(), key=lambda x: -x[1]):
        if score >= threshold:
            print(f"  {a} + {b}  ->  {score:.2f}")

```

What to remember:
- `sorted(..., key=lambda x: -x[1])` sorts by the score, highest first
  - `lambda x: -x[1]` is a tiny anonymous function — `x` is each item, `x[1]` is the score, minus sign reverses the order
- `f"{score:.2f}"` formats the number to 2 decimal places

---

### Step 7 — Wire it all together

```python
def main():
    records = load_data("students.csv")

    course_to_students, student_to_courses = build_mappings(records)
    total_students = len(student_to_courses)

    idf = compute_idf(course_to_students, total_students)

    print("IDF scores (how rare each course is):")
    for course, score in sorted(idf.items(), key=lambda x: -x[1]):
        print(f"  {course}: {score:.3f}")

    print()
    scores = score_pairs(student_to_courses, idf)
    print_results(scores, threshold=0.5)

if __name__ == "__main__":
    main()
```

What to remember:
- `if __name__ == "__main__":` means "only run main() if I run this file directly" — it does not run if another file imports it
- Always call your functions from `main()` and call `main()` at the bottom — keeps the code organised

---

### What to expect when you run it

Carol and Dave should score highest because Databases and Networking are rare (only 2 students share them).
Alice and Bob share Maths and Physics, but those are more common, so their score will be lower.

---

### Key things to remember for this project

| Concept | Why it matters here |
|---------|-------------------|
| `defaultdict(set)` | Lets you build the mappings without checking if a key exists first |
| Set intersection `&` | Finds shared courses between two students in one line |
| `math.log` | Converts raw frequency into a rarity score |
| `enumerate` / `range(i, j)` | How to loop over pairs without repeating |
| `lambda` in `sorted` | How to sort by a specific part of your data |
| `f"{value:.2f}"` | How to control decimal places when printing |
| `if __name__ == "__main__"` | Standard way to make a script safe to import |
