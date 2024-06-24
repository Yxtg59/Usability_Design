<script setup>
import { ref, onMounted } from 'vue';
import axios from 'axios';
import { useRouter } from 'vue-router';
import { useAuthStore } from '../stores/useAuthStore';


const router = useRouter();

// Variables reactivas y autenticación y obtiende el ID del evaluador desde el LocalStorage
const code = ref('');
const designTests = ref([]);
const rol = ref('');
const authStore = useAuthStore();
const evaluatorId = ref(localStorage.getItem('user_id'));

// Al montar el componente, se obtiene el rol del usuario y se cargan las pruebas de diseño si es evaluador
onMounted(async () => {
  rol.value = authStore.role;
  if (rol.value === 'evaluator') {
    await loadDesignTests();
  }
});

// Verifica el código de acceso de la prueba de diseño
const checkDesignTestCode = async () => {
  try {
    const response = await axios.post('http://127.0.0.1:5000/designtests/access', {
      code: code.value,
      evaluator_id: evaluatorId.value
    });
    if (response.status === 200) {
      const newTest = response.data;
      const exists = designTests.value.some(test => test.test_id === newTest.test_id);
      if (!exists) {
        const accessResponse = await axios.get(`http://127.0.0.1:5000/designtests/${newTest.test_id}/check_submission`, {
          params: {
            evaluator_id: evaluatorId.value
          }
        });
        newTest.access_blocked = accessResponse.data.submitted;
        designTests.value.push(newTest);
      } else {
        alert('Esta prueba de diseño ya está en la lista.');
      }
    } else {
      alert('Código no válido o prueba de diseño no encontrada.');
    }
  } catch (error) {
    console.error('Error:', error);
    alert('Ocurrió un error al verificar el código.');
  }
};

// Carga las pruebas de diseño
const loadDesignTests = async () => {
  try {
    const response = await axios.get(`http://127.0.0.1:5000/designtests/access/${evaluatorId.value}`);
    if (response.status === 200) {
      const tests = response.data;
      for (const test of tests) {
        const accessResponse = await axios.get(`http://127.0.0.1:5000/designtests/${test.test_id}/check_submission`, {
          params: {
            evaluator_id: evaluatorId.value
          }
        });
        test.access_blocked = accessResponse.data.submitted;
      }
      designTests.value = tests;
    }
  } catch (error) {
    console.error('Error:', error);
  }
};

// Navega a la página de cuestionarios si no se han enviado todas las respuestas
const goToQuestionnaires = async (testId) => {
  try {
    const response = await axios.get(`http://127.0.0.1:5000/designtests/${testId}/check_submission`, {
      params: {
        evaluator_id: evaluatorId.value
      }
    });
    if (response.status === 200 && response.data.submitted) {
      alert('Ya has enviado todas las respuestas para esta prueba de diseño.');
    } else {
      router.push(`/questionnaires/${testId}`);
    }
  } catch (error) {
    console.error('Error:', error);
  }
};

// Oculta el acceso a una prueba de diseño
const hideDesignTestAccess = async (testId) => {
  try {
    await axios.post(`http://127.0.0.1:5000/designtests/access/${testId}/hide`, {
      evaluator_id: evaluatorId.value
    });
    designTests.value = designTests.value.filter(test => test.test_id !== testId);
    alert('Acceso a la prueba de diseño ocultado exitosamente');
  } catch (error) {
    console.error('Error:', error);
    alert('Ocurrió un error al ocultar el acceso a la prueba de diseño.');
  }
};
</script>

<template>
  <div class="card m-3">
    <div v-if="rol === 'evaluator'">
      <h1 class="text-center mt-3">Pruebas de Diseño</h1>
      <div class="card-body">
        <form @submit.prevent="checkDesignTestCode" class="mb-4">
          <div class="input-group mb-3">
            <input v-model="code" type="text" class="form-control" placeholder="Ingrese el código de la prueba de diseño" />
            <button class="btn btn-primary" type="submit">Verificar Código</button>
          </div>
        </form>
      </div>

      <div class="card mt-3">
        <div class="card-body">
          <table class="table table-primary table-striped-columns" v-if="designTests.length > 0">
            <thead>
              <tr style="text-align: center;">
                <th scope="col">Nombre</th>
                <th scope="col">Descripción</th>
                <th scope="col">URL</th>
                <th scope="col">Tipo</th>
                <th scope="col">Fecha de acceso</th>
                <th scope="col">Acciones</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="test in designTests" :key="test.test_id">
                <td>{{ test.name }}</td>
                <td>{{ test.description }}</td>
                <td style="max-width: 300px; min-width: 300;">{{ test.url }}</td>
                <td>{{ test.test_type }}</td>
                <td>{{ test.created_at }}</td>
                <td>
                  <button @click="goToQuestionnaires(test.test_id)" class="btn btn-secondary" :disabled="test.access_blocked">
                  Responder Cuestionarios</button>
                  <button @click="hideDesignTestAccess(test.test_id)" class="btn btn-danger ms-2">Ocultar</button>
                </td>
              </tr>
            </tbody>
          </table>
          <div v-else>No hay pruebas de diseño para mostrar</div>
        </div>
      </div>
    </div>
    <div v-else>
      <p class="text-danger text-center fs-1">Acceso denegado. Esta página es solo para evaluadores.</p>
    </div>
  </div>
</template>

<style scoped>
.table-responsive {
  margin-top: 20px;
}
</style>
