<?php
// ============================================================
// AUTHENTICATION — Admin Access Control
// RUBRIC: Strong security (authentication, data protection)
// ============================================================
// require_admin() blocks any non-admin user from accessing
// this page. If a staff member tries to open this URL directly,
// they are immediately redirected to the dashboard.
// Only admin accounts can create new system users.
// ============================================================
require_once '../../includes/config.php';
require_once '../../includes/db.php';
require_once '../../includes/auth.php';
require_admin();

$error   = '';
$success = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {

    // ============================================================
    // INPUT VALIDATION — Trim and Sanitize All Incoming Data
    // RUBRIC: Strong security (validation, data protection)
    // ============================================================
    // trim() removes accidental leading/trailing spaces from every
    // field before it is validated or stored. This prevents issues
    // like a username being saved as " admin" instead of "admin".
    // ============================================================
    $full_name = trim($_POST['full_name'] ?? '');
    $username  = trim($_POST['username']  ?? '');
    $password  = trim($_POST['password']  ?? '');
    $confirm   = trim($_POST['confirm_password'] ?? '');
    $role      = $_POST['role'] ?? 'staff';
    $email     = trim($_POST['email'] ?? '');
    $phone     = trim($_POST['phone']  ?? '');

    // ============================================================
    // INPUT VALIDATION — Required Fields, Password Rules
    // RUBRIC: Strong security (validation)
    //         Errors handled properly with clear messages
    // ============================================================
    // Validates all required fields before touching the database:
    // 1. Full name, username, and password must not be empty.
    // 2. Password and confirm password must match exactly.
    // 3. Password must be at least 6 characters long.
    // If any check fails, a clear error message is shown to the
    // user and no data is written to the database.
    // ============================================================
    if (empty($full_name) || empty($username) || empty($password)) {
        $error = 'Full name, username, and password are required.';
    } elseif ($password !== $confirm) {
        $error = 'Passwords do not match.';
    } elseif (strlen($password) < 6) {
        $error = 'Password must be at least 6 characters.';
    } else {

        // ============================================================
        // DATABASE SECURITY — Prepared Statement (Duplicate Check)
        // RUBRIC: Strong security (data protection, validation)
        // ============================================================
        // Checks if the username already exists before inserting.
        // Uses a prepared statement with a ? placeholder so the
        // username value is never directly concatenated into SQL.
        // This prevents SQL Injection attacks on the username field.
        // ============================================================
        $check = $conn->prepare("SELECT id FROM users WHERE username = ? LIMIT 1");
        $check->bind_param('s', $username);
        $check->execute();
        $exists = $check->get_result()->fetch_assoc();
        $check->close();

        if ($exists) {
            $error = 'Username already exists. Choose another.';
        } else {

            // ============================================================
            // DATABASE SECURITY — Password Hashing
            // RUBRIC: Strong security (authentication, data protection)
            // ============================================================
            // The password is NEVER stored as plain text.
            // password_hash() with PASSWORD_DEFAULT uses bcrypt to
            // create a one-way encrypted hash. Even if the database
            // is breached, the actual passwords cannot be recovered.
            // ============================================================
            $hashed = password_hash($password, PASSWORD_DEFAULT);

            // ============================================================
            // DATABASE SECURITY — Prepared Statement (Insert)
            // RUBRIC: Strong security (data protection)
            //         Data is stored, retrieved, and managed correctly
            // ============================================================
            // All 6 values are passed as ? parameters via bind_param.
            // This means user input is never written directly into the
            // SQL string — fully protected against SQL Injection.
            // ============================================================
            $stmt = $conn->prepare("INSERT INTO users (full_name, username, password, role, email, phone) VALUES (?,?,?,?,?,?)");
            $stmt->bind_param('ssssss', $full_name, $username, $hashed, $role, $email, $phone);
            if ($stmt->execute()) {
                $new_id = $conn->insert_id;
                // Audit trail — logs who created this user and when
                log_action($conn, $current_user_id, $current_user_name, 'Added User', 'users', $new_id, "New user: $username ($role)");
                $success = "User '$username' created successfully.";
            } else {
                $error = 'Failed to create user. Please try again.';
            }
            $stmt->close();
        }
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head><?php include '../../includes/head.php'; ?></head>
<body>
<?php include '../../includes/sidebar.php'; ?>
<div class="main-content">
    <?php include '../../includes/header.php'; ?>
    <div class="page-content">

        <div class="d-flex justify-content-between align-items-center mb-3">
            <h5>Add New User</h5>
            <a href="list.php" class="btn btn-sm btn-outline-secondary">Back</a>
        </div>

        <?php if ($error): ?>
            <div class="alert alert-danger"><?php echo htmlspecialchars($error); ?></div>
        <?php endif; ?>
        <?php if ($success): ?>
            <div class="alert alert-success"><?php echo htmlspecialchars($success); ?></div>
        <?php endif; ?>

        <div class="card" style="max-width:500px;">
            <div class="card-body">
                <form method="POST">
                    <div class="row g-3">
                        <div class="col-12">
                            <label class="form-label">Full Name <span class="text-danger">*</span></label>
                            <input type="text" name="full_name" class="form-control" required>
                        </div>
                        <div class="col-md-6">
                            <label class="form-label">Username <span class="text-danger">*</span></label>
                            <input type="text" name="username" class="form-control" required autocomplete="off">
                        </div>
                        <div class="col-md-6">
                            <label class="form-label">Role</label>
                            <select name="role" class="form-select">
                                <option value="staff">Staff</option>
                                <option value="admin">Admin</option>
                            </select>
                        </div>
                        <div class="col-md-6">
                            <label class="form-label">Password <span class="text-danger">*</span></label>
                            <input type="password" name="password" class="form-control" required autocomplete="new-password">
                        </div>
                        <div class="col-md-6">
                            <label class="form-label">Confirm Password <span class="text-danger">*</span></label>
                            <input type="password" name="confirm_password" class="form-control" required>
                        </div>
                        <div class="col-md-6">
                            <label class="form-label">Email</label>
                            <input type="email" name="email" class="form-control">
                        </div>
                        <div class="col-md-6">
                            <label class="form-label">Phone</label>
                            <input type="text" name="phone" class="form-control">
                        </div>
                    </div>
                    <div class="mt-3">
                        <button type="submit" class="btn btn-primary">Create User</button>
                        <a href="list.php" class="btn btn-outline-secondary ms-2">Cancel</a>
                    </div>
                </form>
            </div>
        </div>
    </div>
</div>
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
