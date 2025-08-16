# Split Package (No Code Changes)

This package **does not modify any line** of your original `index.php`.
It only **reorganizes** the project so you can set your webroot to `public/`
while keeping the original code in `src/`.

## Structure
```
split_no_change/
├─ public/
│  └─ index.php      # thin wrapper that includes ../src/index.php
└─ src/
   └─ index.php      # your original file, UNCHANGED
```

## How it works
- `public/index.php` simply runs:
  ```php
  require __DIR__ . '/../src/index.php';
  ```
- Your code executes exactly as before, because it's the same file.
- You can now keep other files (backups, docs) outside the public webroot.

## Deploy
- **XAMPP (Windows):** point your browser to `http://localhost/<project>/public/`.
- **aaPanel/Nginx/Apache:** set the **DocumentRoot** (Website Directory) to the `public/` folder.

Generated: 2025-08-16 10:32:11 UTC
