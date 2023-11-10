import os

absolute_path = os.path.dirname(__file__)
relative_path = "uploads"
full_path = os.path.join(absolute_path, relative_path)

print(absolute_path)