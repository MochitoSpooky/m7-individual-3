
from django.contrib import admin
from django.urls import path, include
from django.contrib.auth import views as auth_views
from tareas.views import bienvenida, CustomLogoutView
from tareas import views
from tareas.views import login_view
from tareas.views import detalle_tarea

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', views.home, name='base'),
    path('login/', login_view, name='login'),
    path('logout/', CustomLogoutView.as_view(next_page='base'), name='logout'),
    path('lista_tareas/', views.lista_tareas, name='lista_tareas'),  # Cambiado a 'tareas' en lugar de 'lista_tareas'
    path('bienvenida/', bienvenida, name='bienvenida'),
    path('accounts/login/', auth_views.LoginView.as_view(template_name='tareas/base.html'), name='base'),
    path('accounts/logout/', auth_views.LogoutView.as_view(), name='logout'),
    path('registro/', views.registro, name='registro'),
    path("agregar/", views.agregar_tarea, name='agregar'),
    path('tarea/<int:tarea_id>/detalle/', detalle_tarea, name='detalle_tarea'),
    path('tarea/<int:tarea_id>/eliminar/', views.eliminar_tarea, name='eliminar_tarea'),
    path('tarea/<int:tarea_id>/completar/', views.completar_tarea, name='completar_tarea'),
    path('tareas/<int:tarea_id>/detalles/', views.detalles_tarea, name='detalles_tarea'),
    path('tareas/<int:tarea_id>/editar/', views.editar_tarea, name='editar_tarea'),
]
