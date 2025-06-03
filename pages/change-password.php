<?php
session_start();
include_once('../includes/config.php');

// Redirect if user is not logged in
if (strlen($_SESSION["edmsid"]) == 0) {
    header('location:logout.php');
} else {
    if (isset($_POST['update'])) {
        $uid = $_SESSION["edmsid"];
        $currentpassword = $_POST['cpass'];
        $newpassword = $_POST['newpass'];

        // Prepared statement to avoid SQL injection
        $stmt = $con->prepare("SELECT id, userPassword FROM tblregistration WHERE id=?");
        $stmt->bind_param("i", $uid);
        $stmt->execute();
        $stmt->store_result();
        $stmt->bind_result($id, $hashedPassword);
        $stmt->fetch();

        if ($stmt->num_rows > 0 && password_verify($currentpassword, $hashedPassword)) {
            // Hash new password and update
            $newHashedPassword = password_hash($newpassword, PASSWORD_BCRYPT);
            $updateStmt = $con->prepare("UPDATE tblregistration SET userPassword=? WHERE id=?");
            $updateStmt->bind_param("si", $newHashedPassword, $uid);
            $updateStmt->execute();

            echo "<script>alert('Password changed successfully.');</script>";
            echo "<script type='text/javascript'> document.location ='change-password.php'; </script>";
        } else {
            echo "<script>alert('Current Password is wrong.');</script>";
            echo "<script type='text/javascript'> document.location ='change-password.php'; </script>";
        }
    }
?>

    <!DOCTYPE html>
    <html lang="en">

    <head>
        <meta charset="utf-8" />
        <meta http-equiv="X-UA-Compatible" content="IE=edge" />
        <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no" />
        <title>e-Diary Management System</title>
        <link href="../css/styles.css" rel="stylesheet" />
        <script src="https://use.fontawesome.com/releases/v6.1.0/js/all.js" crossorigin="anonymous"></script>
        <script type="text/javascript">
            function valid() {
                if (document.chngpwd.newpass.value != document.chngpwd.cnfpass.value) {
                    alert("Password and Confirm Password Field do not match!!");
                    document.chngpwd.cnfpass.focus();
                    return false;
                }
                return true;
            }
        </script>
    </head>

    <body>
        <?php include_once('../includes/header.php'); ?>
        <div id="layoutSidenav">
            <?php include_once('../includes/leftbar.php'); ?>
            <div id="layoutSidenav_content">
                <main>
                    <div class="container-fluid px-4">
                        <h1 class="mt-4"> Change Password</h1>
                        <ol class="breadcrumb mb-4">
                            <li class="breadcrumb-item"><a href="dashboard.php">Dashboard</a></li>
                            <li class="breadcrumb-item active">Change Password</li>
                        </ol>
                        <div class="card mb-4">
                            <div class="card-body">
                                <form method="post" name="chngpwd" onSubmit="return valid();">
                                    <div class="row">
                                        <div class="col-2">Current Password</div>
                                        <div class="col-6">
                                            <input type="password" class="form-control" id="cpass" name="cpass" required="required">
                                        </div>
                                    </div>
                                    <div class="row mt-3">
                                        <div class="col-2">New Password</div>
                                        <div class="col-6">
                                            <input type="password" class="form-control" id="newpass" name="newpass" required>
                                        </div>
                                    </div>
                                    <div class="row mt-3">
                                        <div class="col-2">Confirm Password</div>
                                        <div class="col-6">
                                            <input type="password" class="form-control" id="cnfpass" name="cnfpass" required="required">
                                        </div>
                                    </div>
                                    <div class="row mt-3">
                                        <div class="col-4">&nbsp;</div>
                                        <div class="col-6">
                                            <input type="submit" name="update" id="update" class="btn btn-primary" value="Change" required>
                                        </div>
                                    </div>
                                </form>
                            </div>
                        </div>
                    </div>
                </main>
                <?php include_once('../includes/footer.php'); ?>
            </div>
        </div>
        <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
        <script src="../js/scripts.js"></script>
    </body>

    </html>
<?php } ?>