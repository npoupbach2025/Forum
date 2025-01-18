from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from .models import Category, Topic
from django.contrib import admin
from .models import Report

@admin.register(Report)
class ReportAdmin(admin.ModelAdmin):
    list_display = ('topic', 'reporter', 'reason', 'status', 'created_at')
    list_filter = ('status', 'reason')
    search_fields = ('topic__title', 'reporter__username')
    readonly_fields = ('created_at',)

@admin.register(Category)
class CategoryAdmin(admin.ModelAdmin):
    list_display = ('name', 'created_at')
    search_fields = ('name',)
    ordering = ('-created_at',)

@admin.register(Topic)
class TopicAdmin(admin.ModelAdmin):
    list_display = ('title', 'author', 'created_at')
    list_filter = ('created_at',)
    search_fields = ('title', 'author__username')
    raw_id_fields = ('author',)