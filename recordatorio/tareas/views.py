from django.contrib.auth.decorators import login_required
from django.shortcuts import render, get_object_or_404, redirect
from .models import Tarea, Etiqueta
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.views import LogoutView
from django.contrib.auth.models import User
from .forms import TareaForm

@login_required
def lista_tareas(request):
    usuario = request.user
    tareas = Tarea.objects.filter(usuario=usuario)
    lista_e = Etiqueta.objects.all()
    print(tareas)
    return render(request, 'tareas/lista_tareas.html', {'tareas': tareas,'etiquetas': lista_e})

@login_required
def detalle_tarea(request, tarea_id):
    tarea = get_object_or_404(Tarea, id=tarea_id, usuario=request.user)

    return render(request, 'tareas/lista_tareas.html', {
        'tarea': tarea,
    })


@login_required
def bienvenida(request):
    return render(request, 'tareas/bienvenida.html')

def home(request):
    return render(request, 'tareas/base.html')

def login_view(request):
    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['password']
        user = authenticate(request, username=username, password=password)
        if user is not None:
            login(request, user)
            # Redirigir al usuario a la página correspondiente
            return redirect('bienvenida')  # Reemplaza 'home' con la URL de tu página principal
        else:
            error_message = 'Invalid credentials'
            return render(request, 'tareas/login.html', {'error_message': error_message})
    else:
        return render(request, 'tareas/login.html')

def tareas(request):
    # Lógica para mostrar las tareas del usuario
    return render(request, 'tareas/tareas.html')
@login_required
def agregar_tarea(request):
    if request.method == 'POST':
        form = TareaForm(request.POST)
        if form.is_valid():
            tarea = form.save(commit=False)
            tarea.usuario = request.user
            tarea.save()
            return redirect('lista_tareas')
    else:
        form = TareaForm()
    
    return render(request, 'tareas/agregar.html', {'form': form})


@login_required
def eliminar_tarea(request, tarea_id):
    tarea = get_object_or_404(Tarea, id=tarea_id, usuario=request.user)
    if request.method == 'POST':
        tarea.delete()
    return redirect('lista_tareas')



class CustomLogoutView(LogoutView):
    def dispatch(self, request, *args, **kwargs):
        response = super().dispatch(request, *args, **kwargs)
        if self.redirect_to_login:
            return redirect('base')
        return response

def registro(request):
    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['psw']
        password_repeat = request.POST['psw-repeat']
        first_name = request.POST['first_name']
        last_name = request.POST['last_name']
        email = request.POST['email']

        if password == password_repeat:
            # Verificar si el usuario ya existe
            if User.objects.filter(username=username).exists():
                error_message = 'El usuario ya existe. Intente con otro nombre de usuario.'
                return render(request, 'tareas/registro.html', {'error_message': error_message})
            else:
                # Crear el nuevo usuario
                user = User.objects.create_user(username=username, password=password, first_name=first_name, last_name=last_name, email=email)
                return redirect('bienvenida')
        else:
            error_message = 'Las contraseñas no coinciden.'
            return render(request, 'tareas/registro.html', {'error_message': error_message})
    else:
        return render(request, 'tareas/registro.html')

