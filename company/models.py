from django.db import models
from django.contrib.auth import get_user_model

User = get_user_model()

class Company(models.Model):
    name = models.CharField(max_length=255)
    description = models.TextField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    managers = models.ManyToManyField(
        User,
        related_name="managed_companies",
        limit_choices_to={"role": "manager"},
        blank=True
    )
    vice_managers = models.ManyToManyField(
        User,
        related_name="vice_managed_companies",
        limit_choices_to={"role": "vice_manager"},
        blank=True
    )

    def __str__(self):
        return self.name

class Menu(models.Model):
    company = models.ForeignKey(
        Company,
        on_delete=models.CASCADE,
        related_name="menus"
    )
    name = models.CharField(max_length=255)
    description = models.TextField()
    price = models.DecimalField(max_digits=10, decimal_places=2)
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.name} ({self.company.name})"
