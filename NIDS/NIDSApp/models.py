from django.db import models

# Create your models here.
class NetworkData(models.Model):
    duration = models.FloatField()
    protocol_type = models.CharField(max_length=50)
    service = models.CharField(max_length=100)
    flag = models.CharField(max_length=50)
    src_bytes = models.IntegerField()
    dst_bytes = models.IntegerField()
    urgent = models.IntegerField()
    num_failed_logins = models.IntegerField()
    serror_rate = models.FloatField()
    rerror_rate = models.FloatField()
    attack_type = models.CharField(max_length=50)

    def __str__(self):
        return f"NetworkData - ID: {self.id}, Result: {self.attack_type}"
