angular.module("umbraco").controller("2FactorAuthentication.LoginController",
    function ($scope, $cookies, localizationService, userService, externalLoginInfo, resetPasswordCodeInfo, $timeout, authResource, dialogService) {

        $scope.code = "";
      
        $scope.validate = function (code) {
            $scope.error2FA = "";
            $scope.code = code;
            authResource.verify2FACode("EmailPassword", code)
                .then(function (data) {
                    userService.setAuthenticationSuccessful(data);
                    $scope.submit(true);
                }, function () { $scope.error2FA = "Invalid code entered." });
        };
    });