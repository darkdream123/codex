```markdown
# codex Development Patterns

> Auto-generated skill from repository analysis

## Overview
This skill provides guidance on the development patterns and best practices used in the `codex` TypeScript codebase. It covers file organization, code style, import/export conventions, and testing patterns. While no specific frameworks or automated workflows were detected, this guide will help you contribute code that aligns with the repository's established standards.

## Coding Conventions

### File Naming
- Use **PascalCase** for all file names.
  - **Example:**  
    ```
    MyComponent.ts
    Utils.ts
    ```

### Import Style
- Use **relative imports** for referencing other modules within the codebase.
  - **Example:**
    ```typescript
    import { HelperFunction } from './HelperFunctions';
    ```

### Export Style
- Use **named exports** rather than default exports.
  - **Example:**
    ```typescript
    // In MyModule.ts
    export function doSomething() { ... }
    export const MY_CONSTANT = 42;

    // In another file
    import { doSomething, MY_CONSTANT } from './MyModule';
    ```

### Commit Patterns
- Commit messages are freeform but typically concise (average 56 characters).
- No strict prefixing or conventional commit format enforced.

## Workflows

_No automated or documented workflows were detected in this repository. Below are suggested manual workflows based on common development tasks._

### Adding a New Module
**Trigger:** When creating a new feature or utility.
**Command:** `/add-module`

1. Create a new file using PascalCase (e.g., `NewFeature.ts`).
2. Implement your logic using named exports.
3. Use relative imports to include dependencies.
4. Add corresponding tests in a `.test.ts` file.

### Writing Tests
**Trigger:** When adding or updating code.
**Command:** `/write-test`

1. Create a test file with the pattern `*.test.ts` (e.g., `MyModule.test.ts`).
2. Write tests for all exported functions and constants.
3. Use the project's preferred (undetected) testing framework.

### Importing Code
**Trigger:** When reusing code from another module.
**Command:** `/import-module`

1. Use a relative import path.
2. Import only the named exports you need.
   ```typescript
   import { usefulFunction } from '../Utils';
   ```

## Testing Patterns

- Test files follow the `*.test.ts` naming convention.
- The specific testing framework is not detected; follow existing test file patterns.
- Place tests alongside or near the modules they test.

**Example:**
```typescript
// MyModule.test.ts
import { doSomething } from './MyModule';

describe('doSomething', () => {
  it('should perform its function', () => {
    expect(doSomething()).toBe(true);
  });
});
```

## Commands
| Command         | Purpose                                      |
|-----------------|----------------------------------------------|
| /add-module     | Scaffold a new module with correct conventions |
| /write-test     | Add a new test file for a module              |
| /import-module  | Import named exports using relative paths      |
```
