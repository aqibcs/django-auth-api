from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from django.contrib.auth import authenticate
from rest_framework_simplejwt.tokens import RefreshToken
from account.renderers import UserRenderer
from .serializers import (
    SendPasswordResetEmailSerializer,
    UserChangePasswordSerializer,
    UserPasswordResetSerializer,
    UserRegistrationSerializer,
    UserLoginSerializer,
    UserProfileSerializer,
)


# Helper function to generate tokens for a user
def get_tokens_for_user(user):
    refresh = RefreshToken.for_user(user)
    return {
        'refresh': str(refresh),
        'access': str(refresh.access_token),
    }


# View for User Registration
class UserRegistrationView(APIView):
    renderer_classes = [UserRenderer]

    def post(self, request, format=None):
        serializer = UserRegistrationSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            token = get_tokens_for_user(user)
            return Response(
                {
                    'token': token,
                    'message': 'Registration Successful',
                },
                status=status.HTTP_201_CREATED,
            )
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


# View for User Login
class UserLoginView(APIView):
    renderer_classes = [UserRenderer]

    def post(self, request, format=None):
        serializer = UserLoginSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.data.get('email')
            password = serializer.data.get('password')
            user = authenticate(email=email, password=password)
            if user is not None:
                token = get_tokens_for_user(user)
                return Response(
                    {
                        'token': token,
                        'message': 'Login Successful',
                    },
                    status=status.HTTP_200_OK,
                )
            return Response(
                {
                    'errors': {
                        'non_field_errors': ['Email or Password is not valid']
                    }
                },
                status=status.HTTP_404_NOT_FOUND,
            )
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


# View for retrieving User Profile
class UserProfileView(APIView):
    renderer_classes = [UserRenderer]
    permission_classes = [IsAuthenticated]

    def get(self, request, format=None):
        serializer = UserProfileSerializer(request.user)
        return Response(serializer.data, status=status.HTTP_200_OK)


# View for changing User Password
class UserChangePasswordView(APIView):
    renderer_classes = [UserRenderer]
    permission_classes = [IsAuthenticated]

    def post(self, request, format=None):
        serializer = UserChangePasswordSerializer(
            data=request.data, context={'user': request.user})
        if serializer.is_valid():
            return Response(
                {'message': 'Password Changed Successfully'},
                status=status.HTTP_200_OK,
            )
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


# View for sending Password Reset Email
class SendPasswordResetEmailView(APIView):
    renderer_classes = [UserRenderer]

    def post(self, request, format=None):
        serializer = SendPasswordResetEmailSerializer(data=request.data)
        if serializer.is_valid():
            return Response(
                {
                    'message':
                    'Password Reset link sent. Please check your email.',
                },
                status=status.HTTP_200_OK,
            )
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


# View for resetting Password
class UserPasswordResetView(APIView):
    renderer_classes = [UserRenderer]

    def post(self, request, uid, token, format=None):
        serializer = UserPasswordResetSerializer(data=request.data,
                                                context={
                                                    'uid': uid,
                                                    'token': token
                                                })
        if serializer.is_valid():
            return Response(
                {'message': 'Password Reset Successfully'},
                status=status.HTTP_200_OK,
            )
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
