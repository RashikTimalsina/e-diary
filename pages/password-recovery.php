<?php
session_start();
include("../includes/config.php");

if (isset($_POST['submit'])) {
    $username = $_POST['username'];
    $cnumber = $_POST['contactno'];
    $newpassword = $_POST['inputPassword'];

    // Prepared statement to avoid SQL injection
    $stmt = $con->prepare("SELECT id, userPassword FROM tblregistration WHERE emailId=? AND mobileNumber=?");
    $stmt->bind_param("ss", $username, $cnumber);
    $stmt->execute();
    $stmt->store_result();
    $stmt->bind_result($id, $hashedPassword);
    $stmt->fetch();

    if ($stmt->num_rows > 0) {
        // Hash new password and update
        $newHashedPassword = password_hash($newpassword, PASSWORD_BCRYPT);
        $updateStmt = $con->prepare("UPDATE tblregistration SET userPassword=? WHERE emailId=? AND mobileNumber=?");
        $updateStmt->bind_param("sss", $newHashedPassword, $username, $cnumber);
        $updateStmt->execute();

        echo "<script>alert('Password reset successfully.');</script>";
        echo "<script type='text/javascript'> document.location ='/'; </script>";
    } else {
        echo "<script>alert('Invalid username or Contact Number');</script>";
        echo "<script type='text/javascript'> document.location ='/password-recovery'; </script>";
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
    <script src="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/5.15.3/js/all.min.js" crossorigin="anonymous"></script>
    <script type="text/javascript">
        function valid() {
            if (document.passwordrecovery.inputPassword.value != document.passwordrecovery.cinputPassword.value) {
                alert("Password and Confirm Password Field do not match  !!");
                document.passwordrecovery.cinputPassword.focus();
                return false;
            }
            return true;
        }
    </script>
</head>

<body class="bg-primary">
    <div id="layoutAuthentication">
        <div id="layoutAuthentication_content">
            <main>
                <div class="container">
                    <div class="row justify-content-center">
                        <div class="col-lg-5">
                            <div class="card shadow-lg border-0 rounded-lg mt-5">
                                <div class="card-header">
                                    <h3 class="text-center font-weight-light my-4">e-Diary Management System | Password Recovery</h3>
                                </div>
                                <div class="card-body">
                                    <form method="post" name="passwordrecovery" onSubmit="return valid();">
                                        <div class="form-floating mb-3">
                                            <input class="form-control" id="username" name="username" type="text" placeholder="Username" required />
                                            <label for="username">Emailid</label>
                                        </div>

                                        <div class="form-floating mb-3">
                                            <input class="form-control" id="contactno" name="contactno" type="text" placeholder="Contact Number" required />
                                            <label for="username">Contact No.</label>
                                        </div>

                                        <div class="form-floating mb-3">
                                            <input class="form-control" id="inputPassword" name="inputPassword" type="password" placeholder="Password" required />
                                            <label for="inputPassword">New Password</label>
                                        </div>

                                        <div class="form-floating mb-3">
                                            <input class="form-control" id="cinputPassword" name="cinputPassword" type="password" placeholder="Password" required />
                                            <label for="inputPassword">Confirm Password</label>
                                        </div>

                                        <div class="d-flex align-items-center justify-content-between mt-4 mb-0">
                                            <a class="small" href="../index.php">Back to Home Page</a>
                                            <button type="submit" name="submit" class="btn btn-primary">Submit</button>
                                        </div>
                                    </form>
                                </div>
                                <div class="card-footer text-center py-3">
                                    <div class="small"><a href="../index.php">Back to Home Page</a></div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </main>
        </div>
        <div id="layoutAuthentication_footer">
            <?php include_once('../includes/footer.php'); ?>
        </div>
    </div>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
    <script src="../js/scripts.js"></script>
</body>

</html>