# Generated by Django 3.0.2 on 2020-07-30 10:55

import datetime
from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion
import payingGuest.models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ('accounts', '0001_initial'),
    ]

    operations = [
        migrations.CreateModel(
            name='Amenities',
            fields=[
                ('amenities_id', models.AutoField(primary_key=True, serialize=False)),
                ('amenities_name', models.CharField(max_length=50)),
            ],
            options={
                'verbose_name': 'Amenities',
                'verbose_name_plural': 'Amenities',
                'db_table': 'amenities',
            },
        ),
        migrations.CreateModel(
            name='Room',
            fields=[
                ('room_id', models.AutoField(primary_key=True, serialize=False)),
                ('address', models.CharField(max_length=200)),
                ('description', models.CharField(default='Room for You', max_length=200)),
                ('no_of_beds', models.PositiveIntegerField(default=0)),
                ('vacant_beds', models.PositiveIntegerField(default=0)),
                ('rent_per_bed', models.PositiveIntegerField(default=0)),
                ('deposit', models.PositiveIntegerField(blank=True, default=0, null=True)),
                ('available_from', models.DateTimeField()),
                ('image_path', models.ImageField(default='', upload_to=payingGuest.models.upload_path_handler2)),
                ('amenities', models.CharField(blank=True, default='', max_length=500, null=True)),
                ('gender', models.CharField(choices=[('Male', 'Male'), ('Female', 'Female'), ('Both', 'Both')], max_length=20)),
                ('special_instruction', models.CharField(blank=True, max_length=400, null=True)),
                ('date_posted', models.DateTimeField(default=datetime.datetime(2020, 7, 30, 16, 25, 6, 990536))),
                ('exp_date', models.DateTimeField(default=datetime.datetime(2020, 7, 30, 16, 25, 6, 990536))),
                ('is_active', models.BooleanField(default=False)),
                ('area_id', models.ForeignKey(db_column='area_id', on_delete=django.db.models.deletion.CASCADE, to='accounts.Area')),
                ('user_id', models.ForeignKey(db_column='user_id', on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'verbose_name': 'Room',
                'verbose_name_plural': 'Rooms',
                'db_table': 'rooms',
            },
        ),
        migrations.CreateModel(
            name='RoomsVendorPayment',
            fields=[
                ('pay_id', models.AutoField(primary_key=True, serialize=False)),
                ('amount', models.FloatField()),
                ('date_of_payment', models.DateTimeField(default=datetime.datetime(2020, 7, 30, 16, 25, 6, 992532))),
                ('order_id', models.CharField(default='', max_length=30)),
                ('room_id', models.ForeignKey(db_column='room_id', on_delete=django.db.models.deletion.CASCADE, to='payingGuest.Room')),
                ('user_id', models.ForeignKey(db_column='user_id', on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'verbose_name': 'Room Payment',
                'verbose_name_plural': 'Rooms Payments',
                'db_table': 'rooms_vendor_payment',
            },
        ),
        migrations.CreateModel(
            name='RoomsBookingDetail',
            fields=[
                ('booking_id', models.AutoField(primary_key=True, serialize=False)),
                ('booking_date', models.DateTimeField(default=datetime.datetime(2020, 7, 30, 16, 25, 6, 992532))),
                ('is_active', models.BooleanField(default=True)),
                ('room_id', models.ForeignKey(db_column='room_id', on_delete=django.db.models.deletion.CASCADE, to='payingGuest.Room')),
                ('user_id', models.ForeignKey(db_column='user_id', on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'verbose_name': 'Room Booking',
                'verbose_name_plural': 'Room Bookings',
                'db_table': 'rooms_booking_details',
            },
        ),
        migrations.CreateModel(
            name='RoomImage',
            fields=[
                ('image_id', models.AutoField(primary_key=True, serialize=False)),
                ('image_path', models.ImageField(default='', upload_to=payingGuest.models.upload_path_handler)),
                ('room_id', models.ForeignKey(db_column='room_id', on_delete=django.db.models.deletion.CASCADE, to='payingGuest.Room')),
            ],
            options={
                'verbose_name': 'Room Image',
                'verbose_name_plural': 'Room Images',
                'db_table': 'room_images',
            },
        ),
        migrations.CreateModel(
            name='RoomAppointments',
            fields=[
                ('appoint_id', models.AutoField(primary_key=True, serialize=False)),
                ('sender', models.CharField(max_length=20)),
                ('email', models.EmailField(max_length=1024)),
                ('comment', models.CharField(max_length=600)),
                ('date_posted', models.DateTimeField(default=datetime.datetime(2020, 7, 30, 16, 25, 6, 993527))),
                ('room_id', models.ForeignKey(db_column='room_id', on_delete=django.db.models.deletion.CASCADE, to='payingGuest.Room')),
                ('user_id', models.ForeignKey(db_column='user_id', on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'verbose_name': 'Room Appointment',
                'verbose_name_plural': 'Room Appointments',
                'db_table': 'room_appointments',
            },
        ),
    ]
