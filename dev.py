    def test_user_can_login_after_verification(self):
        response=self.client.post(self.register_url, self.user_data, format="json")
        email=response.data['email']
        user=User.objects.filter(email=email).first()
        user.is_verified=True
        user.is_active=True
        user.save()
        res = self.client.post(self.login_url, self.user_data, format="json")
        self.assertEqual(res.status_code, 200)