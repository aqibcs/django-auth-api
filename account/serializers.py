from rest_framework import serializers
from django.utils.encoding import smart_str, force_bytes, DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.contrib.auth.tokens import PasswordResetTokenGenerator

from account.models import User
from account.utils import Util


# Serializer for User Registration
class UserRegistrationSerializer(serializers.ModelSerializer):
    password2 = serializers.CharField(style={'input_type': 'password'},
                                    write_only=True)

    class Meta:
        model = User
        fields = ['email', 'name', 'password', 'password2', 'tc']
        extra_kwargs = {'password': {'write_only': True}}

    def validate(self, attrs):
        password = attrs.get('password')
        password2 = attrs.get('password2')
        if password != password2:
            raise serializers.ValidationError(
                "Password and Confirm Password doesn't match")
        return attrs

    def create(self, validated_data):
        validated_data.pop('password2')
        return User.objects.create_user(**validated_data)


# Serializer for User Login
class UserLoginSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(max_length=255)

    class Meta:
        model = User
        fields = ['email', 'password']


# Serializer for User Profile
class UserProfileSerializer(serializers.ModelSerializer):

    class Meta:
        model = User
        fields = ['id', 'email', 'name']


# Serializer for Changing User Password
class UserChangePasswordSerializer(serializers.Serializer):
    password = serializers.CharField(max_length=255,
                                    style={'input_type': 'password'},
                                    write_only=True)
    password2 = serializers.CharField(max_length=255,
                                    style={'input_type': 'password'},
                                    write_only=True)

    def validate(self, attrs):
        password = attrs.get('password')
        password2 = attrs.get('password2')
        user = self.context.get('user')
        if password != password2:
            raise serializers.ValidationError(
                "Password and Confirm Password doesn't match")
        user.set_password(password)
        user.save()
        return attrs


# Serializer for Sending Password Reset Email
class SendPasswordResetEmailSerializer(serializers.Serializer):
    email = serializers.EmailField(max_length=255)

    class Meta:
        fields = ['email']

    def validate(self, attrs):
        email = attrs.get('email')
        if User.objects.filter(email=email).exists():
            user = User.objects.get(email=email)
            uid = urlsafe_base64_encode(force_bytes(user.id))
            print('Encoded UID:', uid)
            token = PasswordResetTokenGenerator().make_token(user)
            print('Password Reset Token:', token)
            link = f'http://localhost:3000/api/user/reset/{uid}/{token}'
            print('Password Reset Link:', link)
            body = f"Click the following link to reset your password: {link}"
            data = {
                'email_subject': 'Reset Your Password',
                'email_body': body,
                'to_email': user.email
            }
            Util.send_email(data)
            return attrs
        else:
            raise serializers.ValidationError('You are not a registered user')


# Serializer for User Password Reset
class UserPasswordResetSerializer(serializers.Serializer):
    password = serializers.CharField(max_length=255,
                                    style={'input_type': 'password'},
                                    write_only=True)
    password2 = serializers.CharField(max_length=255,
                                    style={'input_type': 'password'},
                                    write_only=True)

    def validate(self, attrs):
        try:
            password = attrs.get('password')
            password2 = attrs.get('password2')
            uid = self.context.get('uid')
            token = self.context.get('token')
            if password != password2:
                raise serializers.ValidationError(
                    "Password and Confirm Password doesn't match")
            user_id = smart_str(urlsafe_base64_decode(uid))
            user = User.objects.get(id=user_id)
            if not PasswordResetTokenGenerator().check_token(user, token):
                raise serializers.ValidationError(
                    'Token is not valid or expired')
            user.set_password(password)
            user.save()
            return attrs
        except DjangoUnicodeDecodeError:
            raise serializers.ValidationError('Token is not valid or expired')
