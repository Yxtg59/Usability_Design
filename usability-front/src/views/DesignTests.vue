<script setup>
import { ref, onMounted } from 'vue';
import axios from 'axios';
import { useRouter } from 'vue-router';
import { useAuthStore } from '../stores/useAuthStore';

// Inicializa el enrutador y la tienda de autenticación
const router = useRouter();
const authStore = useAuthStore();
const userId = ref(localStorage.getItem('user_id'));

// Variables reactivas
const tests = ref([]);
const showCodes = ref({});
const rol = ref('');

// Datos del formulario y errores
const form = ref({
  name: '',
  url: '',
  description: '',
  testType: '',
  code: '',
});
const errors = ref({
  name: '',
  url: '',
  description: '',
  testType: '',
  code: '',
});

// Al montar el componente, se obtiene el rol y se actualiza la lista de pruebas
onMounted(async () => {
  rol.value = authStore.role;
  await refreshOwnersList();
});

// Validar formulario antes de guardar
const validateCreateForm = async () => {

  // Reinicia los errores del formulario
  errors.value = {
    name: '',
    url: '',
    description: '',
    testType: '',
    code: '',
  };

  // Validaciones de cada campo
  if (!form.value.name) {
    errors.value.name = 'El Nombre de la Prueba es obligatorio.';
  }
  if (!form.value.url) {
    errors.value.url = 'La URL es obligatoria.';
  }
  if (!form.value.description) {
    errors.value.description = 'La Descripción es obligatoria.';
  }
  if (!form.value.testType) {
    errors.value.testType = 'El Tipo de Prueba es obligatorio.';
  }
  if (!form.value.code) {
    errors.value.code = 'El Código es obligatorio.';
  } else {

    // Verifica si el código ya está en uso
    const codeExists = await checkCodeAvailability(form.value.code);
    if (codeExists) {
      errors.value.code = 'Este código ya está en uso. Intenta nuevamente con un código diferente.';
    }
  }

  // Retorna verdadero si no hay errores
  return !Object.values(errors.value).some(error => error !== '');
};

// Verifica si el código ya está en uso
const checkCodeAvailability = async (code) => {
  try {
    const response = await axios.get(`http://127.0.0.1:5000/designtests/checkcode/${code}`);
    return response.data.exists;
  } catch (error) {
    console.error("Error checking code availability", error);
    return false;
  }
};

// Maneja la acción de guardar la prueba de diseño
const handleSaveDesignTest = async () => {
  if (!await validateCreateForm()) {
    return;
  }
  try {
    const requestData = {
      name: form.value.name,
      url: form.value.url,
      description: form.value.description,
      user_id: userId.value,
      test_type: form.value.testType,
      code: form.value.code
    };

    // Envía la solicitud para guardar la prueba de diseño
    const response = await axios.post('http://127.0.0.1:5000/designtests', requestData);
    console.log(response);

    // Actualiza la lista de pruebas y reinicia el formulario
    await refreshOwnersList();

    form.value.name = '';
    form.value.url = '';
    form.value.description = '';
    form.value.testType = '';
    form.value.code = '';
  } catch (error) {
    console.error(error);
    if (error.response && error.response.data.error) {
      alert(error.response.data.error);
    }
  }
};

// Navega a la página para crear un cuestionario
const createQuestionary = (test) => {
  const testUrl = test.url;
  const testType = test.test_type;
  localStorage.setItem('testUrl', testUrl);
  localStorage.setItem('testType', testType);
  router.push({ name: 'questionnaires', params: { testId: test.test_id } });
};

// Navega a la página para ver las respuestas de una prueba
const viewResponses = (test) => {
  router.push({ name: 'responses', params: { testId: test.test_id } });
};

// Elimina una prueba de diseño
const deleteDesignTest = async (test) => {
  if (!confirm('¿Estás seguro de que deseas eliminar esta prueba?')) {
    return;
  }
  try {
    await axios.delete(`http://127.0.0.1:5000/designtests/${test.test_id}`);
    await refreshOwnersList();
  } catch (error) {
    console.error("Error eliminando el cuestionario", error);
  }
};

// Alterna la visibilidad del código
const toggleShowCode = (testId) => {
  showCodes.value[testId] = !showCodes.value[testId];
};

// Actualiza la lista de pruebas de diseño
const refreshOwnersList = async () => {
  const userId = localStorage.getItem('user_id');
  try {
    const response = await axios.get(`http://127.0.0.1:5000/designtests/${userId}`);
    if (response.status === 200) {
      if (response.data.length === 0) {
        tests.value = [];
      } else {
        tests.value = [];
        tests.value.push(...response.data);
      }
    } else {
      console.error(`Error al obtener pruebas de diseño: ${response.status} ${response.statusText}`);
    }
  } catch (error) {
    console.error("Error obteniendo las pruebas de diseño", error);
    tests.value = [];
  }
};
</script>

<template>
  <div class="card m-3">
    <div v-if="rol === 'owner'">
    <h1 class="text-center mt-3">Gestión de pruebas de Diseño</h1>
      <div class="card-body">
        <form @submit.prevent="handleSaveDesignTest">
          <div class="mb-3">
            <label for="name" class="form-label">Nombre de la prueba de diseño</label>
            <input type="text" class="form-control" v-model="form.name" id="name" aria-describedby="nameHelp">
            <div class="text-danger">{{ errors.name }}</div>
          </div>
          <div class="mb-3">
            <label for="url" class="form-label">Enlace de Figma</label>
            <input type="text" class="form-control" v-model="form.url" id="url" aria-describedby="urlHelp">
            <div class="text-danger">{{ errors.url }}</div>
          </div>
          <div class="mb-3">
            <label for="description" class="form-label">Descripción de la prueba de diseño</label>
            <input type="text" class="form-control" v-model="form.description" id="description" aria-describedby="descriptionHelp">
            <div class="text-danger">{{ errors.description }}</div>
          </div>
          <div class="mb-3">
            <label for="testType" class="form-label">Tipo de prueba</label>
            <select class="form-control" v-model="form.testType" id="testType">
              <option value="Movil">Móvil</option>
              <option value="Web">Web</option>
              <option value="Tablet">Tablet</option>
            </select>
            <div class="text-danger">{{ errors.testType }}</div>
          </div>
          <div class="mb-3">
            <label for="code" class="form-label">Código para la prueba de diseño</label>
            <input type="text" class="form-control" v-model="form.code" id="code">
            <div class="text-danger">{{ errors.code }}</div>
          </div>
          <button type="submit" class="btn btn-primary">Añadir Prueba de diseño</button>
        </form>
      </div>
      <div class="card mt-3">
        <div class="card-body">
          <table class="table table-primary table-striped-columns" v-if="tests.length > 0">
            <thead style="text-align: center;">
              <tr>
                <th scope="col">Nombre</th>
                <th scope="col">Descripción</th>
                <th scope="col">Url</th>
                <th scope="col">Tipo</th>
                <th scope="col">Código</th>
                <th scope="col">Fecha de creación</th>
                <th scope="col">Opciones</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="test in tests" :key="test.test_id">
                <td style="text-align: center;">{{ test.name }}</td>
                <td style="max-width: 200px; min-width: 100px;">{{ test.description }}</td>
                <td style="max-width: 200px; min-width: 200px;" >{{ test.url }}</td>
                <td style="max-width: 50px ;min-width: 50px; text-align: center;">{{ test.test_type }}</td>
                <td style="max-width: 50px ;min-width: 50px; text-align: center;">
                  <button @click="toggleShowCode(test.test_id)" class="btn btn-secondary mb-2">
                    {{ showCodes[test.test_id] ? 'Ocultar' : 'Mostrar' }}
                  </button>
                <div>
                  <span v-if="showCodes[test.test_id]">{{ test.code }}</span>
                </div>
                </td>
                <td style="max-width: 50px ;min-width: 50px; text-align: center;">{{ test.created_at }}</td>
                <td style="max-width: 205px ;min-width: 205px;">
                  <button @click="createQuestionary(test)" class="btn btn-primary me-2">Crear Cuestionario</button>
                  <button @click="viewResponses(test)" class="btn btn-info me-2">Ver Respuestas</button>
                  <button @click="deleteDesignTest(test)" class="btn btn-danger">Eliminar</button>
                </td>
              </tr>
            </tbody>
          </table>
          <div v-else>No hay pruebas de diseño para mostrar</div>
        </div>
      </div>
    </div>
    <div v-else>
      <p class="text-danger text-center fs-1">Acceso denegado</p>
    </div>
  </div>
</template>

<style scoped>
.container {
  max-width: 600px;
}
</style>
